#include "replay/executors/dll_executor.h"
#include <Windows.h>
#include <Psapi.h>
#include <algorithm>

std::vector<std::string> DllExecutor::SupportedApis() const {
    return {
        "LoadLibraryW", "LoadLibraryA",
        "LoadLibraryExW", "LoadLibraryExA",
        "GetProcAddress",
        "FreeLibrary",
    };
}

// Returns true if path is under %SystemRoot% (i.e., C:\Windows\...) and can
// be loaded normally (DllMain safe for system DLLs, enables GetProcAddress).
static bool IsWindowsSystemPath(LPCWSTR path) {
    if (!path || path[0] == L'\0') return false;
    wchar_t sysroot[MAX_PATH] = {};
    if (!GetWindowsDirectoryW(sysroot, MAX_PATH)) return false;
    size_t n = wcslen(sysroot);
    return (_wcsnicmp(path, sysroot, n) == 0 &&
            (path[n] == L'\\' || path[n] == L'\0'));
}

static bool IsWindowsSystemPathA(LPCSTR path) {
    if (!path) return false;
    wchar_t wide[MAX_PATH] = {};
    MultiByteToWideChar(CP_ACP, 0, path, -1, wide, MAX_PATH);
    return IsWindowsSystemPath(wide);
}

// Load a DLL with safety:
//  - If already loaded → return existing handle (GetProcAddress works, no DllMain).
//  - System DLL (C:\Windows\...) with no DATAFILE flag in original request →
//    load normally so GetProcAddress works correctly.
//  - Everything else → LOAD_LIBRARY_AS_DATAFILE to prevent DllMain on malware paths.
static HMODULE SafeLoadW(LPCWSTR path, DWORD orig_flags) {
    if (!path) return nullptr;
    HMODULE h = GetModuleHandleW(path);
    if (h) return h;
    if (IsWindowsSystemPath(path) && !(orig_flags & LOAD_LIBRARY_AS_DATAFILE)) {
        // Strip flags that require extra path setup (e.g. LOAD_WITH_ALTERED_SEARCH_PATH)
        // but keep meaningful flags like LOAD_LIBRARY_SEARCH_SYSTEM32.
        DWORD safe_flags = orig_flags & (LOAD_LIBRARY_SEARCH_SYSTEM32 |
                                         LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
        h = LoadLibraryExW(path, nullptr, safe_flags);
        if (h) return h;
    }
    return LoadLibraryExW(path, nullptr,
                          LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
}

static HMODULE SafeLoadA(LPCSTR path, DWORD orig_flags) {
    if (!path) return nullptr;
    HMODULE h = GetModuleHandleA(path);
    if (h) return h;
    if (IsWindowsSystemPathA(path) && !(orig_flags & LOAD_LIBRARY_AS_DATAFILE)) {
        DWORD safe_flags = orig_flags & (LOAD_LIBRARY_SEARCH_SYSTEM32 |
                                         LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
        h = LoadLibraryExA(path, nullptr, safe_flags);
        if (h) return h;
    }
    return LoadLibraryExA(path, nullptr,
                          LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
}

DWORD_PTR DllExecutor::Execute(const LogEvent& event, const PreparedArgs& p) {
    const auto& n = event.api_name;

    if (n == "LoadLibraryW")   return (DWORD_PTR)SafeLoadW((LPCWSTR)p.raw[0], 0);
    if (n == "LoadLibraryA")   return (DWORD_PTR)SafeLoadA((LPCSTR)p.raw[0],  0);
    if (n == "LoadLibraryExW") return (DWORD_PTR)SafeLoadW((LPCWSTR)p.raw[0], (DWORD)p.raw[2]);
    if (n == "LoadLibraryExA") return (DWORD_PTR)SafeLoadA((LPCSTR)p.raw[0],  (DWORD)p.raw[2]);

    if (n == "GetProcAddress") {
        HMODULE hmod = (HMODULE)p.raw[0];
        LPCSTR  proc = (LPCSTR)p.raw[1];
        if (!proc) return 0;
        if (hmod) {
            FARPROC fp = GetProcAddress(hmod, proc);
            if (fp) return (DWORD_PTR)fp;
        }
        // Fallback: search all currently loaded modules.
        // Useful when hmod is NULL (malware DLL load failed) or a DATAFILE handle
        // (GetProcAddress returns NULL on DATAFILE handles).  Many malware-requested
        // exports (send, recv, RegQueryValueExW, etc.) are present in system DLLs
        // that are already loaded in the replay process.
        HMODULE mods[512]; DWORD cb = 0;
        if (EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &cb)) {
            DWORD n_mods = std::min(cb / (DWORD)sizeof(HMODULE), (DWORD)512);
            for (DWORD i = 0; i < n_mods; i++) {
                FARPROC fp = GetProcAddress(mods[i], proc);
                if (fp) return (DWORD_PTR)fp;
            }
        }
        return 0;
    }

    if (n == "FreeLibrary") {
        HMODULE h = (HMODULE)p.raw[0];
        if (!h) return (DWORD_PTR)TRUE;
        return (DWORD_PTR)FreeLibrary(h);
    }

    return 0;
}
