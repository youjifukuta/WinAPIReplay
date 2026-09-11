#include "replay/executors/sync_executor.h"

std::vector<std::string> SyncExecutor::SupportedApis() const {
    return {
        "CreateMutexW", "CreateMutexA",
        "OpenMutexW", "OpenMutexA",
        "ReleaseMutex",
        "CreateEventW", "CreateEventA",
        "SetEvent", "ResetEvent",
        "WaitForSingleObject",
        "WaitForMultipleObjects",
        "WaitForMultipleObjectsEx",
    };
}

DWORD_PTR SyncExecutor::Execute(const LogEvent& event, const PreparedArgs& p) {
    const auto& n = event.api_name;

    if (n == "CreateMutexW")
        return (DWORD_PTR)CreateMutexW(nullptr, (BOOL)p.raw[1], (LPCWSTR)p.raw[2]);
    if (n == "CreateMutexA")
        return (DWORD_PTR)CreateMutexA(nullptr, (BOOL)p.raw[1], (LPCSTR)p.raw[2]);
    if (n == "OpenMutexW")
        return (DWORD_PTR)OpenMutexW((DWORD)p.raw[0], (BOOL)p.raw[1], (LPCWSTR)p.raw[2]);
    if (n == "OpenMutexA")
        return (DWORD_PTR)OpenMutexA((DWORD)p.raw[0], (BOOL)p.raw[1], (LPCSTR)p.raw[2]);
    if (n == "ReleaseMutex")
        return (DWORD_PTR)ReleaseMutex((HANDLE)p.raw[0]);

    if (n == "CreateEventW")
        return (DWORD_PTR)CreateEventW(nullptr, (BOOL)p.raw[1], (BOOL)p.raw[2], (LPCWSTR)p.raw[3]);
    if (n == "CreateEventA")
        return (DWORD_PTR)CreateEventA(nullptr, (BOOL)p.raw[1], (BOOL)p.raw[2], (LPCSTR)p.raw[3]);
    if (n == "SetEvent")
        return (DWORD_PTR)SetEvent((HANDLE)p.raw[0]);
    if (n == "ResetEvent")
        return (DWORD_PTR)ResetEvent((HANDLE)p.raw[0]);

    if (n == "WaitForSingleObject") {
        // Replace logged timeout with configured timeout to avoid deadlocks
        return (DWORD_PTR)WaitForSingleObject((HANDLE)p.raw[0], timeout_ms_);
    }
    if (n == "WaitForMultipleObjects") {
        DWORD count = (DWORD)p.raw[0];
        const HANDLE* handles = p.args[1].handle_arr.empty()
                                ? nullptr
                                : p.args[1].handle_arr.data();
        if (!handles) return WAIT_FAILED;
        return (DWORD_PTR)WaitForMultipleObjects(
            count, handles, (BOOL)p.raw[2], timeout_ms_);
    }
    if (n == "WaitForMultipleObjectsEx") {
        DWORD count = (DWORD)p.raw[0];
        const HANDLE* handles = p.args[1].handle_arr.empty()
                                ? nullptr
                                : p.args[1].handle_arr.data();
        if (!handles) return WAIT_FAILED;
        return (DWORD_PTR)WaitForMultipleObjectsEx(
            count, handles, (BOOL)p.raw[2], timeout_ms_, (BOOL)p.raw[4]);
    }

    return 0;
}
