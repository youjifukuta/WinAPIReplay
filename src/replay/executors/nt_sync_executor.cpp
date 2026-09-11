#include "replay/executors/nt_sync_executor.h"
#include "replay/nt_native.h"
#include "replay/utils.h"
#include <windows.h>

// WinMET argument layout for NT sync APIs:
//   NtCreate*  : [0]=out_handle [1]=DesiredAccess [2]=OA_ptr [3]=OA.ObjectName [4..]=type/initial/count
//   NtOpen*    : [0]=out_handle [1]=DesiredAccess [2]=OA_ptr [3]=OA.ObjectName
//   NtRelease* : [0]=handle
//   NtClose    : [0]=handle

// ── Helpers ───────────────────────────────────────────────────────────────────

DWORD_PTR NtSyncExecutor::ReadHexArg(const LogEvent& event, int idx) {
    if (idx >= (int)event.args.size()) return 0;
    if (auto* ws = std::get_if<std::wstring>(&event.args[idx])) {
        try { return HexToPtr(WideToUtf8(*ws)); } catch (...) { return 0; }
    }
    if (auto* iv = std::get_if<std::int64_t>(&event.args[idx]))
        return (DWORD_PTR)*iv;
    return 0;
}

std::wstring NtSyncExecutor::ReadStrArg(const LogEvent& event, int idx) {
    if (idx >= (int)event.args.size()) return {};
    if (auto* ws = std::get_if<std::wstring>(&event.args[idx])) return *ws;
    return {};
}

SIZE_T NtSyncExecutor::ReadSizeArg(const LogEvent& event, int idx) {
    return (SIZE_T)ReadHexArg(event, idx);
}

// Build OBJECT_ATTRIBUTES from NT object name (e.g., "\BaseNamedObjects\Name").
// us and oa storage must outlive the NT call.
static void BuildSyncOA(const std::wstring& name, UNICODE_STRING& us, OBJECT_ATTRIBUTES& oa) {
    if (!name.empty()) {
        NtInitUnicodeString(us, name);
        InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
    } else {
        us = {};
        InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);
    }
}

// Convert wait_timeout_ms to NT LARGE_INTEGER (relative, 100ns units; negative = relative).
static LARGE_INTEGER ToNtTimeout(DWORD ms) {
    LARGE_INTEGER li;
    li.QuadPart = -(LONGLONG)ms * 10000LL;
    return li;
}

// ── SupportedApis ─────────────────────────────────────────────────────────────

std::vector<std::string> NtSyncExecutor::SupportedApis() const {
    return {
        "NtClose",                "ZwClose",
        "NtWaitForSingleObject",
        "NtWaitForMultipleObjects",
        "NtCreateMutant",         "ZwCreateMutant",
        "NtOpenMutant",           "ZwOpenMutant",
        "NtReleaseMutant",        "ZwReleaseMutant",
        "NtCreateEvent",          "ZwCreateEvent",
        "NtOpenEvent",            "ZwOpenEvent",
        "NtSetEvent",
        "NtResetEvent",
        "NtCreateSemaphore",      "ZwCreateSemaphore",
        "NtOpenSemaphore",
        "NtCreateTimer",          "ZwCreateTimer",
        "NtOpenTimer",
        "NtCreateIoCompletion",   "ZwCreateIoCompletion",
        "NtOpenIoCompletion",
        "NtCreateJobObject",      "NtOpenJobObject",
        "NtCreateDebugObject",    "DbgUiConnectToDbg",
    };
}

// ── Execute ───────────────────────────────────────────────────────────────────

DWORD_PTR NtSyncExecutor::Execute(const LogEvent& event, const PreparedArgs&) {
    const auto& n   = event.api_name;
    const NtApi& nt = GetNtApi();

    // ── NtClose ───────────────────────────────────────────────────────────────
    if (n == "NtClose" || n == "ZwClose") {
        if (!nt.NtClose) return 0;
        DWORD_PTR orig_h = ReadHexArg(event, 0);
        if (!orig_h) return 0;
        DWORD_PTR real_h = handle_map_.Resolve(orig_h);
        if (real_h && real_h != orig_h) {
            NTSTATUS status = nt.NtClose((HANDLE)real_h);
            handle_map_.Invalidate(orig_h);
            return (DWORD_PTR)status;
        }
        return 0;
    }

    // ── NtWaitForSingleObject ─────────────────────────────────────────────────
    if (n == "NtWaitForSingleObject") {
        if (!nt.NtWaitForSingleObject) return 0;
        DWORD_PTR orig_h = ReadHexArg(event, 0);
        DWORD_PTR real_h = handle_map_.Resolve(orig_h);
        if (real_h && real_h != orig_h) {
            LARGE_INTEGER timeout = ToNtTimeout(wait_timeout_ms_);
            return (DWORD_PTR)nt.NtWaitForSingleObject((HANDLE)real_h, FALSE, &timeout);
        }
        return 0;  // STATUS_SUCCESS (approx: unmapped handle)
    }

    // ── NtWaitForMultipleObjects ──────────────────────────────────────────────
    // Cannot reconstruct handle array from log; return STATUS_SUCCESS as approx.
    if (n == "NtWaitForMultipleObjects") return 0;

    // ── NtCreateMutant ────────────────────────────────────────────────────────
    if (n == "NtCreateMutant" || n == "ZwCreateMutant") {
        if (!nt.NtCreateMutant) return 0;
        DWORD_PTR orig_h = ReadHexArg(event, 0);
        if (orig_h && handle_map_.HasMapping(orig_h)) return 0;
        ULONG access      = (ULONG)ReadHexArg(event, 1);
        if (!access) access = MUTANT_ALL_ACCESS;
        std::wstring name = ReadStrArg(event, 3);
        BOOLEAN initial   = (BOOLEAN)ReadSizeArg(event, 4);

        UNICODE_STRING us = {}; OBJECT_ATTRIBUTES oa = {};
        BuildSyncOA(name, us, oa);

        HANDLE h = nullptr;
        NTSTATUS status = nt.NtCreateMutant(&h, access,
                                             name.empty() ? nullptr : &oa, initial);
        if (h && orig_h) handle_map_.Register(orig_h, (DWORD_PTR)h);
        return (DWORD_PTR)status;
    }

    // ── NtOpenMutant ─────────────────────────────────────────────────────────
    if (n == "NtOpenMutant" || n == "ZwOpenMutant") {
        if (!nt.NtOpenMutant) return 0;
        DWORD_PTR orig_h = ReadHexArg(event, 0);
        if (orig_h && handle_map_.HasMapping(orig_h)) return 0;
        ULONG access      = (ULONG)ReadHexArg(event, 1);
        if (!access) access = MUTANT_ALL_ACCESS;
        std::wstring name = ReadStrArg(event, 3);

        UNICODE_STRING us = {}; OBJECT_ATTRIBUTES oa = {};
        BuildSyncOA(name, us, oa);

        HANDLE h = nullptr;
        NTSTATUS status = nt.NtOpenMutant(&h, access, name.empty() ? nullptr : &oa);
        if (NT_SUCCESS(status) && h && orig_h)
            handle_map_.Register(orig_h, (DWORD_PTR)h);
        return (DWORD_PTR)status;
    }

    // ── NtReleaseMutant ───────────────────────────────────────────────────────
    if (n == "NtReleaseMutant" || n == "ZwReleaseMutant") {
        if (!nt.NtReleaseMutant) return 0;
        DWORD_PTR orig_h = ReadHexArg(event, 0);
        DWORD_PTR real_h = handle_map_.Resolve(orig_h);
        if (real_h && real_h != orig_h)
            return (DWORD_PTR)nt.NtReleaseMutant((HANDLE)real_h, nullptr);
        return 0;
    }

    // ── NtCreateEvent ─────────────────────────────────────────────────────────
    if (n == "NtCreateEvent" || n == "ZwCreateEvent") {
        if (!nt.NtCreateEvent) return 0;
        DWORD_PTR orig_h   = ReadHexArg(event, 0);
        if (orig_h && handle_map_.HasMapping(orig_h)) return 0;
        ULONG access       = (ULONG)ReadHexArg(event, 1);
        if (!access) access = EVENT_ALL_ACCESS;
        std::wstring name  = ReadStrArg(event, 3);
        ULONG event_type   = (ULONG)ReadSizeArg(event, 4);  // 0=Sync, 1=Notification
        BOOLEAN init_state = (BOOLEAN)ReadSizeArg(event, 5);

        UNICODE_STRING us = {}; OBJECT_ATTRIBUTES oa = {};
        BuildSyncOA(name, us, oa);

        HANDLE h = nullptr;
        NTSTATUS status = nt.NtCreateEvent(&h, access,
                                            name.empty() ? nullptr : &oa,
                                            event_type, init_state);
        if (h && orig_h) handle_map_.Register(orig_h, (DWORD_PTR)h);
        return (DWORD_PTR)status;
    }

    // ── NtOpenEvent ───────────────────────────────────────────────────────────
    if (n == "NtOpenEvent" || n == "ZwOpenEvent") {
        if (!nt.NtOpenEvent) return 0;
        DWORD_PTR orig_h  = ReadHexArg(event, 0);
        if (orig_h && handle_map_.HasMapping(orig_h)) return 0;
        ULONG access      = (ULONG)ReadHexArg(event, 1);
        if (!access) access = EVENT_ALL_ACCESS;
        std::wstring name = ReadStrArg(event, 3);

        UNICODE_STRING us = {}; OBJECT_ATTRIBUTES oa = {};
        BuildSyncOA(name, us, oa);

        HANDLE h = nullptr;
        NTSTATUS status = nt.NtOpenEvent(&h, access, name.empty() ? nullptr : &oa);
        if (NT_SUCCESS(status) && h && orig_h)
            handle_map_.Register(orig_h, (DWORD_PTR)h);
        return (DWORD_PTR)status;
    }

    // ── NtSetEvent ────────────────────────────────────────────────────────────
    if (n == "NtSetEvent") {
        if (!nt.NtSetEvent) return 0;
        DWORD_PTR orig_h = ReadHexArg(event, 0);
        DWORD_PTR real_h = handle_map_.Resolve(orig_h);
        if (real_h && real_h != orig_h)
            return (DWORD_PTR)nt.NtSetEvent((HANDLE)real_h, nullptr);
        return 0;
    }

    // ── NtResetEvent ──────────────────────────────────────────────────────────
    if (n == "NtResetEvent") {
        if (!nt.NtResetEvent) return 0;
        DWORD_PTR orig_h = ReadHexArg(event, 0);
        DWORD_PTR real_h = handle_map_.Resolve(orig_h);
        if (real_h && real_h != orig_h)
            return (DWORD_PTR)nt.NtResetEvent((HANDLE)real_h, nullptr);
        return 0;
    }

    // ── NtCreateSemaphore ─────────────────────────────────────────────────────
    if (n == "NtCreateSemaphore" || n == "ZwCreateSemaphore") {
        if (!nt.NtCreateSemaphore) return 0;
        DWORD_PTR orig_h   = ReadHexArg(event, 0);
        if (orig_h && handle_map_.HasMapping(orig_h)) return 0;
        ULONG access       = (ULONG)ReadHexArg(event, 1);
        if (!access) access = SEMAPHORE_ALL_ACCESS;
        std::wstring name  = ReadStrArg(event, 3);
        LONG init_count    = (LONG)ReadSizeArg(event, 4);
        LONG max_count     = (LONG)ReadSizeArg(event, 5);
        if (max_count <= 0) max_count = 1;

        UNICODE_STRING us = {}; OBJECT_ATTRIBUTES oa = {};
        BuildSyncOA(name, us, oa);

        HANDLE h = nullptr;
        NTSTATUS status = nt.NtCreateSemaphore(&h, access,
                                                name.empty() ? nullptr : &oa,
                                                init_count, max_count);
        if (h && orig_h) handle_map_.Register(orig_h, (DWORD_PTR)h);
        return (DWORD_PTR)status;
    }

    // ── NtOpenSemaphore ───────────────────────────────────────────────────────
    if (n == "NtOpenSemaphore") {
        if (!nt.NtOpenSemaphore) return 0;
        DWORD_PTR orig_h  = ReadHexArg(event, 0);
        if (orig_h && handle_map_.HasMapping(orig_h)) return 0;
        ULONG access      = (ULONG)ReadHexArg(event, 1);
        if (!access) access = SEMAPHORE_ALL_ACCESS;
        std::wstring name = ReadStrArg(event, 3);

        UNICODE_STRING us = {}; OBJECT_ATTRIBUTES oa = {};
        BuildSyncOA(name, us, oa);

        HANDLE h = nullptr;
        NTSTATUS status = nt.NtOpenSemaphore(&h, access, name.empty() ? nullptr : &oa);
        if (NT_SUCCESS(status) && h && orig_h)
            handle_map_.Register(orig_h, (DWORD_PTR)h);
        return (DWORD_PTR)status;
    }

    // ── NtCreateTimer ─────────────────────────────────────────────────────────
    if (n == "NtCreateTimer" || n == "ZwCreateTimer") {
        if (!nt.NtCreateTimer) return 0;
        DWORD_PTR orig_h  = ReadHexArg(event, 0);
        if (orig_h && handle_map_.HasMapping(orig_h)) return 0;
        ULONG access      = (ULONG)ReadHexArg(event, 1);
        if (!access) access = TIMER_ALL_ACCESS;
        std::wstring name = ReadStrArg(event, 3);
        ULONG type        = (ULONG)ReadSizeArg(event, 4);  // 0=NotificationTimer, 1=SynchronizationTimer

        UNICODE_STRING us = {}; OBJECT_ATTRIBUTES oa = {};
        BuildSyncOA(name, us, oa);

        HANDLE h = nullptr;
        NTSTATUS status = nt.NtCreateTimer(&h, access,
                                            name.empty() ? nullptr : &oa, type);
        if (h && orig_h) handle_map_.Register(orig_h, (DWORD_PTR)h);
        return (DWORD_PTR)status;
    }

    // ── NtOpenTimer ───────────────────────────────────────────────────────────
    if (n == "NtOpenTimer") {
        if (!nt.NtOpenTimer) return 0;
        DWORD_PTR orig_h  = ReadHexArg(event, 0);
        if (orig_h && handle_map_.HasMapping(orig_h)) return 0;
        ULONG access      = (ULONG)ReadHexArg(event, 1);
        if (!access) access = TIMER_ALL_ACCESS;
        std::wstring name = ReadStrArg(event, 3);

        UNICODE_STRING us = {}; OBJECT_ATTRIBUTES oa = {};
        BuildSyncOA(name, us, oa);

        HANDLE h = nullptr;
        NTSTATUS status = nt.NtOpenTimer(&h, access, name.empty() ? nullptr : &oa);
        if (NT_SUCCESS(status) && h && orig_h)
            handle_map_.Register(orig_h, (DWORD_PTR)h);
        return (DWORD_PTR)status;
    }

    // ── NtCreateIoCompletion ──────────────────────────────────────────────────
    if (n == "NtCreateIoCompletion" || n == "ZwCreateIoCompletion") {
        if (!nt.NtCreateIoCompletion) return 0;
        DWORD_PTR orig_h = ReadHexArg(event, 0);
        if (orig_h && handle_map_.HasMapping(orig_h)) return 0;
        ULONG access = (ULONG)ReadHexArg(event, 1);
        if (!access) access = 0x1F0003;  // IO_COMPLETION_ALL_ACCESS
        // args[2]=OA ptr, args[3]=ConcurrentThreads (WinMET doesn't extract OA.ObjectName for IOCP)
        ULONG count = (ULONG)ReadSizeArg(event, 3);

        HANDLE h = nullptr;
        NTSTATUS status = nt.NtCreateIoCompletion(&h, access, nullptr, count);
        if (h && orig_h) handle_map_.Register(orig_h, (DWORD_PTR)h);
        return (DWORD_PTR)status;
    }

    // ── NtOpenIoCompletion ────────────────────────────────────────────────────
    if (n == "NtOpenIoCompletion") {
        if (!nt.NtOpenIoCompletion) return 0;
        DWORD_PTR orig_h  = ReadHexArg(event, 0);
        if (orig_h && handle_map_.HasMapping(orig_h)) return 0;
        ULONG access      = (ULONG)ReadHexArg(event, 1);
        if (!access) access = 0x1F0003;
        std::wstring name = ReadStrArg(event, 3);

        UNICODE_STRING us = {}; OBJECT_ATTRIBUTES oa = {};
        BuildSyncOA(name, us, oa);

        HANDLE h = nullptr;
        NTSTATUS status = nt.NtOpenIoCompletion(&h, access, name.empty() ? nullptr : &oa);
        if (NT_SUCCESS(status) && h && orig_h)
            handle_map_.Register(orig_h, (DWORD_PTR)h);
        return (DWORD_PTR)status;
    }

    // ── NtCreateJobObject ─────────────────────────────────────────────────────
    if (n == "NtCreateJobObject") {
        if (!nt.NtCreateJobObject) return 0;
        DWORD_PTR orig_h  = ReadHexArg(event, 0);
        if (orig_h && handle_map_.HasMapping(orig_h)) return 0;
        ULONG access      = (ULONG)ReadHexArg(event, 1);
        if (!access) access = JOB_OBJECT_ALL_ACCESS;
        std::wstring name = ReadStrArg(event, 2);

        UNICODE_STRING us = {}; OBJECT_ATTRIBUTES oa = {};
        BuildSyncOA(name, us, oa);

        HANDLE h = nullptr;
        NTSTATUS status = nt.NtCreateJobObject(&h, access, name.empty() ? nullptr : &oa);
        if (h && orig_h) handle_map_.Register(orig_h, (DWORD_PTR)h);
        return (DWORD_PTR)status;
    }

    // ── NtOpenJobObject ───────────────────────────────────────────────────────
    if (n == "NtOpenJobObject") {
        if (!nt.NtOpenJobObject) return 0;
        DWORD_PTR orig_h  = ReadHexArg(event, 0);
        if (orig_h && handle_map_.HasMapping(orig_h)) return 0;
        ULONG access      = (ULONG)ReadHexArg(event, 1);
        if (!access) access = JOB_OBJECT_ALL_ACCESS;
        std::wstring name = ReadStrArg(event, 2);

        UNICODE_STRING us = {}; OBJECT_ATTRIBUTES oa = {};
        BuildSyncOA(name, us, oa);

        HANDLE h = nullptr;
        NTSTATUS status = nt.NtOpenJobObject(&h, access, name.empty() ? nullptr : &oa);
        if (NT_SUCCESS(status) && h && orig_h)
            handle_map_.Register(orig_h, (DWORD_PTR)h);
        return (DWORD_PTR)status;
    }

    // ── NtCreateDebugObject ───────────────────────────────────────────────────
    if (n == "NtCreateDebugObject") {
        if (!nt.NtCreateDebugObject) return 0;
        DWORD_PTR orig_h = ReadHexArg(event, 0);
        if (orig_h && handle_map_.HasMapping(orig_h)) return 0;
        ULONG access = (ULONG)ReadHexArg(event, 1);
        if (!access) access = 0x1F000F;  // DEBUG_ALL_ACCESS

        HANDLE h = nullptr;
        NTSTATUS status = nt.NtCreateDebugObject(&h, access, nullptr, 0);
        if (h && orig_h) handle_map_.Register(orig_h, (DWORD_PTR)h);
        return (DWORD_PTR)status;
    }

    // ── DbgUiConnectToDbg ─────────────────────────────────────────────────────
    if (n == "DbgUiConnectToDbg") {
        // Stub: do NOT connect the replay process to the debug subsystem.
        // The real function attaches WinAPIReplay.exe itself as a debugger UI via
        // a kernel debug object — a persistent side effect that persists across samples
        // and can interfere with NT sync operations in subsequent events.
        // Malware uses this as an anti-debugging probe; returning 0 (STATUS_SUCCESS)
        // satisfies the call without any actual attachment.
        return 0;
    }

    return 0;
}
