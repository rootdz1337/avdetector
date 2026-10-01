# avdetector
av detector gui

 GUI version of your antivirus detector using the Win32 API. It creates a window with a list view showing detected antivirus products and a refresh button.

1. **`wmain` → `wWinMain`** with the standard Windows GUI entry point.
2. **`WndProc`** handles window messages (`WM_CREATE`, `WM_SIZE`, `WM_COMMAND`, `WM_NOTIFY`, `WM_DESTROY`).
3. **ListView** (`WC_LISTVIEWW`) with 5 columns: `#`, Name, Version, State, Executable Path.
4. **Refresh button** re-runs the WMI query without restarting the app.
5. **Status bar** (a `STATIC` control) shows the count of detected products.
6. **Double-click a row** shows the full executable path in a message box.
7. **Modern font** (Segoe UI) applied to all controls.
8. **Resizable layout** — the ListView and columns resize with the window.
9. **`CoUninitialize` safety** — only called if `CoInitializeEx` succeeded (avoids undefined behavior).
10. **COM is initialized once** at startup rather than per-scan, so refresh doesn't need to re-init.

## Build instructions (MSVC)

```
cl /EHsc /W3 avdetector.cpp /link user32.lib gdi32.lib comctl32.lib wbemuuid.lib ole32.lib oleaut32.lib
```

Or in Visual Studio: create a **Windows Desktop Application** project, replace the generated `.cpp`, add `wbemuuid.lib` and `comctl32.lib` to the linker inputs, and set the subsystem to **Windows** (`/SUBSYSTEM:WINDOWS`).


- Requires **Windows Vista+** (`ROOT\SecurityCenter2` namespace).
- If you get "Could not connect to WMI namespace", ensure the **Windows Management Instrumentation** service is running and you're not in a restricted environment.
- The `productState` field is a raw bitmask; you can decode it (e.g., bits 12–15 for enabled/up-to-date status) if you want human-readable states like "On / Up to date".
