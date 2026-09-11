#include "replay/generic_dispatcher.h"
#include "replay/utils.h"
#include <psapi.h>
#include <vector>
#include <string>
#include <iostream>

typedef DWORD_PTR(__cdecl *AnyFunc)(
    DWORD_PTR, DWORD_PTR, DWORD_PTR, DWORD_PTR,
    DWORD_PTR, DWORD_PTR, DWORD_PTR, DWORD_PTR,
    DWORD_PTR, DWORD_PTR, DWORD_PTR, DWORD_PTR,
    DWORD_PTR, DWORD_PTR, DWORD_PTR, DWORD_PTR
);

// SEH is incompatible with C++ destructors in the same scope → separate function
static bool SafeCallImpl(AnyFunc fn, DWORD_PTR* raw, DWORD_PTR& out) {
    __try {
        out = fn(raw[0],  raw[1],  raw[2],  raw[3],
                 raw[4],  raw[5],  raw[6],  raw[7],
                 raw[8],  raw[9],  raw[10], raw[11],
                 raw[12], raw[13], raw[14], raw[15]);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool GenericDispatcher::Dispatch(const LogEvent& event, DWORD_PTR& out_result) {
    // Enumerate all loaded modules
    HANDLE hProc = GetCurrentProcess();
    std::vector<HMODULE> mods(1024);
    DWORD cbNeeded = 0;
    if (!EnumProcessModules(hProc, mods.data(), (DWORD)(mods.size() * sizeof(HMODULE)), &cbNeeded))
        return false;
    size_t count = cbNeeded / sizeof(HMODULE);

    const std::string& api = event.api_name;

    FARPROC fp = nullptr;
    for (size_t i = 0; i < count && !fp; i++) {
        fp = GetProcAddress(mods[i], api.c_str());
    }
    if (!fp) return false;

    // Build raw args: int64_t → HandleMap.Resolve; wstring → wchar_t*; nullptr_t → 0
    // Keep buffer alive for the duration of the call
    std::vector<std::vector<BYTE>> bufs(event.args.size());
    std::vector<DWORD_PTR> raw(16, 0);

    for (int i = 0; i < (int)event.args.size() && i < 16; i++) {
        const auto& v = event.args[i];
        if (std::holds_alternative<std::nullptr_t>(v)) {
            raw[i] = 0;
        } else if (std::holds_alternative<std::int64_t>(v)) {
            // Always pass 0 for integer args in Layer2.
            // Using SafeResolve here caused heap corruption: a non-handle integer
            // (e.g., a buffer-size like 1024) that coincidentally matches a registered
            // handle value gets translated to the actual WinAPIReplay handle value
            // (e.g., 0x400), which the callee then uses as an output-buffer length,
            // writing far beyond the small buffer we allocated → heap corruption.
            raw[i] = 0;
        } else if (std::holds_alternative<std::wstring>(v)) {
            const std::wstring& ws = std::get<std::wstring>(v);
            bufs[i].resize((ws.size() + 1) * sizeof(wchar_t), 0);
            wcscpy_s(reinterpret_cast<wchar_t*>(bufs[i].data()), ws.size() + 1, ws.c_str());
            raw[i] = reinterpret_cast<DWORD_PTR>(bufs[i].data());
        }
    }

    AnyFunc fn = reinterpret_cast<AnyFunc>(fp);
    if (!SafeCallImpl(fn, raw.data(), out_result)) {
        std::cerr << "[WARN] Layer2 SEH caught: " << api << "\n";
        return false;
    }
    return true;
}
