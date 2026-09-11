#include "replay/executors/system_executor.h"
#include <Windows.h>

std::vector<std::string> SystemExecutor::SupportedApis() const {
    return {
        // Struct-init-dependent APIs: cbSize / dwLength must be set before
        // the call.  GenericDispatcher cannot do this because it passes 0 for
        // all integer args, leaving the struct pointer as NULL.
        "GetLastInputInfo",
        "GetComputerNameW",    "GetComputerNameA",
        "GetComputerNameExW",  "GetComputerNameExA",
        "GlobalMemoryStatusEx",
        // System-info query APIs: output buffer is a local that we discard.
        "GetSystemTimeAsFileTime",
        "GetSystemTime",       "GetLocalTime",
        "GetSystemInfo",       "GetNativeSystemInfo",
        "GetUserNameW",        "GetUserNameA",
        // NT-level time / memory-watch APIs
        "NtQuerySystemTime",
        "GetWriteWatch",
    };
}

DWORD_PTR SystemExecutor::Execute(const LogEvent& event, const PreparedArgs& /*p*/) {
    const std::string& n = event.api_name;

    // ── Input-device query ───────────────────────────────────────────────────
    if (n == "GetLastInputInfo") {
        LASTINPUTINFO lii{};
        lii.cbSize = sizeof(LASTINPUTINFO);
        return (DWORD_PTR)GetLastInputInfo(&lii);
    }

    // ── Computer-name queries ─────────────────────────────────────────────────
    if (n == "GetComputerNameW") {
        wchar_t buf[MAX_COMPUTERNAME_LENGTH + 1] = {};
        DWORD sz = MAX_COMPUTERNAME_LENGTH + 1;
        return (DWORD_PTR)GetComputerNameW(buf, &sz);
    }
    if (n == "GetComputerNameA") {
        char buf[MAX_COMPUTERNAME_LENGTH + 1] = {};
        DWORD sz = MAX_COMPUTERNAME_LENGTH + 1;
        return (DWORD_PTR)GetComputerNameA(buf, &sz);
    }
    if (n == "GetComputerNameExW") {
        // arg[0] = COMPUTER_NAME_FORMAT (int64 captured from original process)
        COMPUTER_NAME_FORMAT fmt = ComputerNameDnsHostname;
        if (!event.args.empty()) {
            if (auto* iv = std::get_if<std::int64_t>(&event.args[0]))
                fmt = (COMPUTER_NAME_FORMAT)*iv;
        }
        wchar_t buf[256] = {};
        DWORD sz = 256;
        return (DWORD_PTR)GetComputerNameExW(fmt, buf, &sz);
    }
    if (n == "GetComputerNameExA") {
        COMPUTER_NAME_FORMAT fmt = ComputerNameDnsHostname;
        if (!event.args.empty()) {
            if (auto* iv = std::get_if<std::int64_t>(&event.args[0]))
                fmt = (COMPUTER_NAME_FORMAT)*iv;
        }
        char buf[256] = {};
        DWORD sz = 256;
        return (DWORD_PTR)GetComputerNameExA(fmt, buf, &sz);
    }

    // ── Memory status ─────────────────────────────────────────────────────────
    if (n == "GlobalMemoryStatusEx") {
        MEMORYSTATUSEX ms{};
        ms.dwLength = sizeof(MEMORYSTATUSEX);
        return (DWORD_PTR)GlobalMemoryStatusEx(&ms);
    }

    // ── Time queries ──────────────────────────────────────────────────────────
    if (n == "GetSystemTimeAsFileTime") {
        FILETIME ft{};
        GetSystemTimeAsFileTime(&ft);
        return 1;  // VOID return, always success
    }
    if (n == "GetSystemTime") {
        SYSTEMTIME st{};
        GetSystemTime(&st);
        return 1;
    }
    if (n == "GetLocalTime") {
        SYSTEMTIME st{};
        GetLocalTime(&st);
        return 1;
    }
    if (n == "NtQuerySystemTime") {
        // Use GetSystemTimeAsFileTime; both return LARGE_INTEGER / FILETIME.
        FILETIME ft{};
        GetSystemTimeAsFileTime(&ft);
        return 0;  // STATUS_SUCCESS
    }

    // ── System-info queries ───────────────────────────────────────────────────
    if (n == "GetSystemInfo") {
        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        return 1;
    }
    if (n == "GetNativeSystemInfo") {
        SYSTEM_INFO si{};
        GetNativeSystemInfo(&si);
        return 1;
    }

    // ── User-name queries ─────────────────────────────────────────────────────
    if (n == "GetUserNameW") {
        wchar_t buf[256] = {};
        DWORD sz = 256;
        return (DWORD_PTR)GetUserNameW(buf, &sz);
    }
    if (n == "GetUserNameA") {
        char buf[256] = {};
        DWORD sz = 256;
        return (DWORD_PTR)GetUserNameA(buf, &sz);
    }

    // ── Write-watch ───────────────────────────────────────────────────────────
    if (n == "GetWriteWatch") {
        // Cannot call with a valid VirtualAlloc'd MEM_WRITE_WATCH region in
        // the replay context.  Report 0 dirty pages (success, no pages reset).
        return 0;
    }

    return 0;
}
