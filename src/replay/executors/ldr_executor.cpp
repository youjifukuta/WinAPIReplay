#include "replay/executors/ldr_executor.h"
#include "replay/nt_native.h"
#include "replay/utils.h"
#include <windows.h>

// WinMET argument layout for Ldr APIs:
//   LdrLoadDll                     : [0]=out_DllBase_hex  [1]=SearchPath  [2]=DLL name/path
//   LdrGetDllHandle / Ex / ByName  : [0]=out_DllBase_hex  [1]=name
//   LdrGetProcedureAddressForCaller: [0]=module_handle_hex  [1]=proc_name_str  [2..3]=out_proc_addr_hex

// ── Helpers ───────────────────────────────────────────────────────────────────

DWORD_PTR LdrExecutor::ReadHexArg(const LogEvent& event, int idx) {
    if (idx >= (int)event.args.size()) return 0;
    if (auto* ws = std::get_if<std::wstring>(&event.args[idx])) {
        try { return HexToPtr(WideToUtf8(*ws)); } catch (...) { return 0; }
    }
    if (auto* iv = std::get_if<std::int64_t>(&event.args[idx]))
        return (DWORD_PTR)*iv;
    return 0;
}

std::wstring LdrExecutor::ReadStrArg(const LogEvent& event, int idx) {
    if (idx >= (int)event.args.size()) return {};
    if (auto* ws = std::get_if<std::wstring>(&event.args[idx])) return *ws;
    return {};
}

// ── SupportedApis ─────────────────────────────────────────────────────────────

std::vector<std::string> LdrExecutor::SupportedApis() const {
    return {
        "LdrLoadDll",
        "LdrGetDllHandle",        "LdrGetDllHandleEx",
        "LdrGetDllHandleByName",
        "LdrGetProcedureAddressForCaller",
    };
}

// ── Execute ───────────────────────────────────────────────────────────────────

DWORD_PTR LdrExecutor::Execute(const LogEvent& event, const PreparedArgs&) {
    const auto& n   = event.api_name;
    const NtApi& nt = GetNtApi();

    // ── LdrLoadDll ─────────────────────────────────────────────────────────────
    // Single LdrLoadDll call via ntdll; no LoadLibraryExW fallback.
    if (n == "LdrLoadDll") {
        if (!nt.LdrLoadDll) return (DWORD_PTR)0xC0000135;  // STATUS_DLL_NOT_FOUND
        DWORD_PTR orig_h  = ReadHexArg(event, 0);
        std::wstring name = ReadStrArg(event, 2);
        if (name.empty()) name = ReadStrArg(event, 1);
        if (name.empty()) return (DWORD_PTR)0xC0000135;

        UNICODE_STRING us_name;
        NtInitUnicodeString(us_name, name);

        PVOID dll_base = nullptr;
        NTSTATUS status = nt.LdrLoadDll(nullptr, nullptr, &us_name, &dll_base);

        if (NT_SUCCESS(status) && dll_base && orig_h)
            handle_map_.Register(orig_h, (DWORD_PTR)dll_base);
        return (DWORD_PTR)status;
    }

    // ── LdrGetDllHandle / LdrGetDllHandleEx / LdrGetDllHandleByName ───────────
    // Single LdrGetDllHandle call; no LoadLibraryExW fallback.
    if (n == "LdrGetDllHandle"     ||
        n == "LdrGetDllHandleEx"   ||
        n == "LdrGetDllHandleByName") {
        DWORD_PTR orig_h  = ReadHexArg(event, 0);
        std::wstring name = ReadStrArg(event, 1);
        if (name.empty() && event.args.size() > 2) name = ReadStrArg(event, 2);

        PVOID dll_base = nullptr;
        NTSTATUS status = 0xC0000135;  // STATUS_DLL_NOT_FOUND

        if (!name.empty()) {
            UNICODE_STRING us_name;
            NtInitUnicodeString(us_name, name);

            if (n == "LdrGetDllHandleEx" && nt.LdrGetDllHandleEx) {
                status = nt.LdrGetDllHandleEx(0, nullptr, nullptr, &us_name, &dll_base);
            } else if (nt.LdrGetDllHandle) {
                status = nt.LdrGetDllHandle(nullptr, nullptr, &us_name, &dll_base);
            }
        }

        if (NT_SUCCESS(status) && dll_base && orig_h)
            handle_map_.Register(orig_h, (DWORD_PTR)dll_base);
        return (DWORD_PTR)status;
    }

    // ── LdrGetProcedureAddressForCaller ────────────────────────────────────────
    // Single LdrGetProcedureAddress call via ntdll; no GetProcAddress fallback.
    if (n == "LdrGetProcedureAddressForCaller") {
        if (!nt.LdrGetProcedureAddress) return (DWORD_PTR)0xC000007A;  // STATUS_PROCEDURE_NOT_FOUND
        DWORD_PTR orig_mod       = ReadHexArg(event, 0);
        std::wstring proc_name_w = ReadStrArg(event, 1);
        DWORD_PTR orig_addr      = ReadHexArg(event, 2);
        if (!orig_addr && event.args.size() > 3)
            orig_addr = ReadHexArg(event, 3);

        PVOID hmod = (PVOID)handle_map_.Resolve(orig_mod);
        if (!hmod) return (DWORD_PTR)0xC000007A;

        std::string proc_a = WideToUtf8(proc_name_w);
        ANSI_STRING as;
        as.Buffer        = proc_a.empty() ? nullptr : (PCHAR)proc_a.c_str();
        as.Length        = (USHORT)proc_a.size();
        as.MaximumLength = as.Length + 1;

        PVOID proc = nullptr;
        NTSTATUS status = nt.LdrGetProcedureAddress(hmod, &as, 0, &proc);

        if (NT_SUCCESS(status) && proc && orig_addr)
            pointer_map_.Register(orig_addr, (DWORD_PTR)proc);
        return (DWORD_PTR)status;
    }

    return 0;
}
