#define UNICODE
#define _UNICODE

#include <windows.h>
#include <commctrl.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <string>
#include <vector>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "comctl32.lib")

// Control IDs
#define IDC_LISTVIEW    1001
#define IDC_REFRESH     1002
#define IDC_STATUS      1003

// Window class name
const wchar_t* WINDOW_CLASS = L"AntivirusDetectorWindow";

// Global window handles
HWND g_hWnd = nullptr;
HWND g_hListView = nullptr;
HWND g_hRefreshBtn = nullptr;
HWND g_hStatus = nullptr;

// ============================================================================
// AntivirusDetector class (unchanged core logic)
// ============================================================================
class AntivirusDetector {
private:
    IWbemLocator* pLoc = nullptr;
    IWbemServices* pSvc = nullptr;
    bool comInitialized = false;

public:
    AntivirusDetector() = default;

    ~AntivirusDetector() {
        if (pSvc) pSvc->Release();
        if (pLoc) pLoc->Release();
        if (comInitialized) CoUninitialize();
    }

    bool Initialize() {
        HRESULT hres;

        hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hres)) {
            return false;
        }
        comInitialized = true;

        hres = CoInitializeSecurity(
            NULL, -1, NULL, NULL,
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL, EOAC_NONE, NULL
        );

        if (FAILED(hres) && hres != RPC_E_TOO_LATE) {
            return false;
        }

        hres = CoCreateInstance(
            CLSID_WbemLocator, 0,
            CLSCTX_INPROC_SERVER,
            IID_IWbemLocator,
            (LPVOID*)&pLoc
        );

        if (FAILED(hres)) return false;

        hres = pLoc->ConnectServer(
            _bstr_t(L"ROOT\\SecurityCenter2"),
            NULL, NULL, 0, NULL, 0, 0, &pSvc
        );

        if (FAILED(hres)) return false;

        hres = CoSetProxyBlanket(
            pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
            NULL, RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL, EOAC_NONE
        );

        if (FAILED(hres)) return false;

        return true;
    }

    struct AntivirusInfo {
        std::wstring name;
        std::wstring pathToSignedProductExe;
        std::wstring version;
        std::wstring state;
    };

    std::vector<AntivirusInfo> GetAntivirusProducts() {
        std::vector<AntivirusInfo> antivirusList;

        if (!pSvc) return antivirusList;

        IEnumWbemClassObject* pEnumerator = nullptr;
        HRESULT hres = pSvc->ExecQuery(
            bstr_t("WQL"),
            bstr_t("SELECT * FROM AntiVirusProduct"),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL,
            &pEnumerator
        );

        if (FAILED(hres)) return antivirusList;

        IWbemClassObject* pclsObj = nullptr;
        ULONG uReturn = 0;

        while (pEnumerator) {
            HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
            if (0 == uReturn) break;

            VARIANT vtProp;
            AntivirusInfo avInfo;

            hr = pclsObj->Get(L"displayName", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR)
                avInfo.name = vtProp.bstrVal;
            VariantClear(&vtProp);

            hr = pclsObj->Get(L"pathToSignedProductExe", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR)
                avInfo.pathToSignedProductExe = vtProp.bstrVal;
            VariantClear(&vtProp);

            hr = pclsObj->Get(L"versionNumber", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR)
                avInfo.version = vtProp.bstrVal;
            VariantClear(&vtProp);

            hr = pclsObj->Get(L"productState", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hr)) {
                if (vtProp.vt == VT_I4) {
                    wchar_t buf[32];
                    swprintf(buf, 32, L"0x%08X", vtProp.intVal);
                    avInfo.state = buf;
                } else if (vtProp.vt == VT_BSTR) {
                    avInfo.state = vtProp.bstrVal;
                }
            }
            VariantClear(&vtProp);

            antivirusList.push_back(avInfo);
            pclsObj->Release();
        }

        pEnumerator->Release();
        return antivirusList;
    }
};

// Global detector instance
AntivirusDetector g_detector;

// ============================================================================
// Helper: Initialize ListView columns
// ============================================================================
void SetupListView(HWND hList) {
    ListView_SetExtendedListViewStyle(hList,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

    LVCOLUMN lvc = { 0 };
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

    lvc.iSubItem = 0;
    lvc.pszText = (LPWSTR)L"#";
    lvc.cx = 40;
    ListView_InsertColumn(hList, 0, &lvc);

    lvc.iSubItem = 1;
    lvc.pszText = (LPWSTR)L"Name";
    lvc.cx = 220;
    ListView_InsertColumn(hList, 1, &lvc);

    lvc.iSubItem = 2;
    lvc.pszText = (LPWSTR)L"Version";
    lvc.cx = 130;
    ListView_InsertColumn(hList, 2, &lvc);

    lvc.iSubItem = 3;
    lvc.pszText = (LPWSTR)L"State";
    lvc.cx = 110;
    ListView_InsertColumn(hList, 3, &lvc);

    lvc.iSubItem = 4;
    lvc.pszText = (LPWSTR)L"Executable Path";
    lvc.cx = 380;
    ListView_InsertColumn(hList, 4, &lvc);
}

// ============================================================================
// Helper: Populate ListView with AV products
// ============================================================================
void RefreshAntivirusList() {
    ListView_DeleteAllItems(g_hListView);

    auto products = g_detector.GetAntivirusProducts();

    if (products.empty()) {
        SetWindowTextW(g_hStatus, L"No antivirus products detected.");
        return;
    }

    for (size_t i = 0; i < products.size(); ++i) {
        const auto& av = products[i];

        LVITEM lvi = { 0 };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = (int)i;
        lvi.iSubItem = 0;

        wchar_t idx[16];
        swprintf(idx, 16, L"%zu", i + 1);
        lvi.pszText = idx;
        int row = ListView_InsertItem(g_hListView, &lvi);

        ListView_SetItemText(g_hListView, row, 1, (LPWSTR)av.name.c_str());
        ListView_SetItemText(g_hListView, row, 2, (LPWSTR)av.version.c_str());
        ListView_SetItemText(g_hListView, row, 3, (LPWSTR)av.state.c_str());
        ListView_SetItemText(g_hListView, row, 4,
            (LPWSTR)av.pathToSignedProductExe.c_str());
    }

    wchar_t status[128];
    swprintf(status, 128, L"Detected %zu antivirus product(s).",
        products.size());
    SetWindowTextW(g_hStatus, status);
}

// ============================================================================
// Window Procedure
// ============================================================================
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        // Create ListView
        g_hListView = CreateWindowExW(
            0, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | WS_BORDER,
            10, 10, 880, 400,
            hWnd, (HMENU)IDC_LISTVIEW,
            ((LPCREATESTRUCT)lParam)->hInstance, NULL);

        SetupListView(g_hListView);

        // Create Refresh button
        g_hRefreshBtn = CreateWindowExW(
            0, L"BUTTON", L"Refresh",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            10, 420, 120, 32,
            hWnd, (HMENU)IDC_REFRESH,
            ((LPCREATESTRUCT)lParam)->hInstance, NULL);

        // Create status label
        g_hStatus = CreateWindowExW(
            0, L"STATIC", L"Scanning...",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            150, 427, 740, 24,
            hWnd, (HMENU)IDC_STATUS,
            ((LPCREATESTRUCT)lParam)->hInstance, NULL);

        // Set a modern-ish font
        HFONT hFont = CreateFontW(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        SendMessage(g_hListView, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessage(g_hRefreshBtn, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessage(g_hStatus, WM_SETFONT, (WPARAM)hFont, TRUE);

        // Initial scan
        RefreshAntivirusList();
        return 0;
    }

    case WM_SIZE: {
        RECT rc;
        GetClientRect(hWnd, &rc);

        int margin = 10;
        int btnHeight = 32;
        int statusHeight = 24;
        int listHeight = rc.bottom - margin * 3 - btnHeight - statusHeight;

        SetWindowPos(g_hListView, NULL,
            margin, margin,
            rc.right - margin * 2, listHeight,
            SWP_NOZORDER);

        SetWindowPos(g_hRefreshBtn, NULL,
            margin, rc.bottom - margin - btnHeight,
            120, btnHeight,
            SWP_NOZORDER);

        SetWindowPos(g_hStatus, NULL,
            150, rc.bottom - margin - statusHeight - 4,
            rc.right - 160, statusHeight,
            SWP_NOZORDER);

        // Resize columns proportionally
        int totalWidth = rc.right - margin * 2;
        if (totalWidth > 100) {
            ListView_SetColumnWidth(g_hListView, 0, 40);
            ListView_SetColumnWidth(g_hListView, 1, totalWidth * 25 / 100);
            ListView_SetColumnWidth(g_hListView, 2, totalWidth * 15 / 100);
            ListView_SetColumnWidth(g_hListView, 3, totalWidth * 12 / 100);
            ListView_SetColumnWidth(g_hListView, 4,
                totalWidth - 40 - totalWidth * 52 / 100);
        }
        return 0;
    }

    case WM_COMMAND: {
        if (LOWORD(wParam) == IDC_REFRESH) {
            SetWindowTextW(g_hStatus, L"Scanning...");
            UpdateWindow(g_hStatus);
            RefreshAntivirusList();
        }
        return 0;
    }

    case WM_NOTIFY: {
        LPNMHDR lpnmh = (LPNMHDR)lParam;
        if (lpnmh->idFrom == IDC_LISTVIEW &&
            lpnmh->code == NM_DBLCLK) {
            // Double-click: show full path in a message box
            LPNMITEMACTIVATE lpnmitem = (LPNMITEMACTIVATE)lParam;
            if (lpnmitem->iItem >= 0) {
                wchar_t path[MAX_PATH] = { 0 };
                ListView_GetItemText(g_hListView, lpnmitem->iItem, 4,
                    path, MAX_PATH);
                if (path[0]) {
                    MessageBoxW(hWnd, path, L"Executable Path",
                        MB_OK | MB_ICONINFORMATION);
                }
            }
        }
        return 0;
    }

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// ============================================================================
// WinMain
// ============================================================================
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
    PWSTR pCmdLine, int nCmdShow) {

    // Initialize common controls
    INITCOMMONCONTROLSEX icex = { 0 };
    icex.dwSize = sizeof(icex);
    icex.dwICC = ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icex);

    // Initialize COM + WMI
    if (!g_detector.Initialize()) {
        MessageBoxW(NULL,
            L"Failed to initialize antivirus detector.\n"
            L"Make sure you have appropriate permissions and WMI is available.",
            L"Initialization Error",
            MB_OK | MB_ICONERROR);
        return 1;
    }

    // Register window class
    WNDCLASSEXW wc = { 0 };
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = WINDOW_CLASS;
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);

    if (!RegisterClassExW(&wc)) {
        MessageBoxW(NULL, L"Window registration failed.",
            L"Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    // Create main window
    g_hWnd = CreateWindowExW(
        0, WINDOW_CLASS,
        L"Antivirus Detector",
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        CW_USEDEFAULT, CW_USEDEFAULT, 920, 520,
        NULL, NULL, hInstance, NULL);

    if (!g_hWnd) {
        MessageBoxW(NULL, L"Window creation failed.",
            L"Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    ShowWindow(g_hWnd, nCmdShow);
    UpdateWindow(g_hWnd);

    // Message loop
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        if (!IsDialogMessage(g_hWnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    return (int)msg.wParam;
}
