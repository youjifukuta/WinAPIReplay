#include "replay/executors/shell_executor.h"
#include <shellapi.h>

std::vector<std::string> ShellExecutor::SupportedApis() const {
    return { "ShellExecuteW", "ShellExecuteA", "WinExec" };
}

DWORD_PTR ShellExecutor::Execute(const LogEvent& event, const PreparedArgs& p) {
    const auto& n = event.api_name;

    // ShellExecuteW/A return value > 32 means success; WinExec > 31 means success.
    // Return 33 to signal blocked-but-succeeded when no_spawn_ is active.
    if (no_spawn_) return 33;

    if (n == "ShellExecuteW") {
        return (DWORD_PTR)ShellExecuteW(
            (HWND)p.raw[0], (LPCWSTR)p.raw[1], (LPCWSTR)p.raw[2],
            (LPCWSTR)p.raw[3], (LPCWSTR)p.raw[4], (INT)p.raw[5]);
    }
    if (n == "ShellExecuteA") {
        return (DWORD_PTR)ShellExecuteA(
            (HWND)p.raw[0], (LPCSTR)p.raw[1], (LPCSTR)p.raw[2],
            (LPCSTR)p.raw[3], (LPCSTR)p.raw[4], (INT)p.raw[5]);
    }
    if (n == "WinExec") {
        // ArgPreparer builds a wchar_t buffer for WSTRING args.
        // WinExec takes LPCSTR (system ANSI); convert with CP_ACP, not CP_UTF8.
        const wchar_t* wcmd = reinterpret_cast<const wchar_t*>(p.raw[0]);
        if (!wcmd) return (DWORD_PTR)ERROR_FILE_NOT_FOUND;
        int len = WideCharToMultiByte(CP_ACP, 0, wcmd, -1, nullptr, 0, nullptr, nullptr);
        std::string cmd(len > 0 ? len : 1, '\0');
        WideCharToMultiByte(CP_ACP, 0, wcmd, -1, cmd.data(), len, nullptr, nullptr);
        return (DWORD_PTR)WinExec(cmd.c_str(), (UINT)p.raw[1]);
    }

    return 0;
}
