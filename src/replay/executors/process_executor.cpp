#include "replay/executors/process_executor.h"
#include <windows.h>

typedef LONG (NTAPI *PfnNtUnmap)(HANDLE, PVOID);

std::vector<std::string> ProcessExecutor::SupportedApis() const {
    return {
        "CreateProcessW", "CreateProcessA",
        "OpenProcess",
        "TerminateProcess",
        "GetExitCodeProcess",
        "VirtualAlloc",
        "VirtualAllocEx",
        "VirtualFree",
        "VirtualProtect",
        "WriteProcessMemory",
        "ReadProcessMemory",
        "CreateThread",
        "CreateRemoteThread",
        "QueueUserAPC",
        "NtUnmapViewOfSection",
    };
}

static DWORD WINAPI DummyThreadProc(LPVOID) { return 0; }

DWORD_PTR ProcessExecutor::Execute(const LogEvent& event, const PreparedArgs& p) {
    const auto& n = event.api_name;

    if (n == "CreateProcessW") {
        if (no_spawn_) {
            // Synthesize success: fill PROCESS_INFORMATION with current process handles
            // so subsequent Wait/ReadProcessMemory calls have a valid (if wrong) handle.
            auto* pi = reinterpret_cast<PROCESS_INFORMATION*>(p.raw[9]);
            if (pi) {
                pi->hProcess    = GetCurrentProcess();
                pi->hThread     = GetCurrentThread();
                pi->dwProcessId = GetCurrentProcessId();
                pi->dwThreadId  = GetCurrentThreadId();
            }
            return (DWORD_PTR)TRUE;
        }
        auto* si = reinterpret_cast<STARTUPINFOW*>(p.raw[8]);
        if (si) si->cb = sizeof(STARTUPINFOW);
        return (DWORD_PTR)CreateProcessW(
            (LPCWSTR)p.raw[0], (LPWSTR)p.raw[1],
            nullptr, nullptr, (BOOL)p.raw[4], (DWORD)p.raw[5],
            nullptr, (LPCWSTR)p.raw[7],
            si, (LPPROCESS_INFORMATION)p.raw[9]);
    }
    if (n == "CreateProcessA") {
        if (no_spawn_) {
            auto* pi = reinterpret_cast<PROCESS_INFORMATION*>(p.raw[9]);
            if (pi) {
                pi->hProcess    = GetCurrentProcess();
                pi->hThread     = GetCurrentThread();
                pi->dwProcessId = GetCurrentProcessId();
                pi->dwThreadId  = GetCurrentThreadId();
            }
            return (DWORD_PTR)TRUE;
        }
        auto* si = reinterpret_cast<STARTUPINFOA*>(p.raw[8]);
        if (si) si->cb = sizeof(STARTUPINFOA);
        return (DWORD_PTR)CreateProcessA(
            (LPCSTR)p.raw[0], (LPSTR)p.raw[1],
            nullptr, nullptr, (BOOL)p.raw[4], (DWORD)p.raw[5],
            nullptr, (LPCSTR)p.raw[7],
            si, (LPPROCESS_INFORMATION)p.raw[9]);
    }

    if (n == "OpenProcess") {
        DWORD pid    = (DWORD)p.raw[2];
        DWORD access = (DWORD)p.raw[0];
        // Unknown/unmapped PID: open current process as substitute
        if (pid == 0) pid = GetCurrentProcessId();
        if (access == 0) access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
        HANDLE h = OpenProcess(access, (BOOL)p.raw[1], pid);
        if (!h) h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!h) h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        return (DWORD_PTR)h;
    }

    if (n == "TerminateProcess") {
        // Never terminate; return success silently
        return (DWORD_PTR)TRUE;
    }

    if (n == "GetExitCodeProcess") {
        HANDLE h = (HANDLE)p.raw[0];
        if (!h) return (DWORD_PTR)TRUE;
        return (DWORD_PTR)GetExitCodeProcess(h, (LPDWORD)p.raw[1]);
    }

    if (n == "VirtualAlloc") {
        return (DWORD_PTR)VirtualAlloc(
            nullptr, (SIZE_T)p.raw[1], (DWORD)p.raw[2], (DWORD)p.raw[3]);
    }
    if (n == "VirtualAllocEx") {
        return (DWORD_PTR)VirtualAllocEx(
            (HANDLE)p.raw[0], nullptr, (SIZE_T)p.raw[2], (DWORD)p.raw[3], (DWORD)p.raw[4]);
    }
    if (n == "VirtualFree") {
        return (DWORD_PTR)TRUE;
    }
    if (n == "VirtualProtect") {
        LPVOID addr  = (LPVOID)p.raw[0];
        SIZE_T size  = (SIZE_T)p.raw[1];
        DWORD  prot  = (DWORD)p.raw[2];
        LPDWORD old  = (LPDWORD)p.raw[3];
        // Null address or zero size: nothing to protect → success
        if (!addr || size == 0) return (DWORD_PTR)TRUE;
        BOOL r = VirtualProtect(addr, size, prot, old);
        // If the address belongs to a different process mapping → success anyway
        if (!r) r = TRUE;
        return (DWORD_PTR)r;
    }

    if (n == "WriteProcessMemory") {
        // With no_spawn or unmapped handle: no real target process → succeed silently
        if (no_spawn_ || !p.raw[0]) return (DWORD_PTR)TRUE;
        SIZE_T written = 0;
        BOOL r = WriteProcessMemory(
            (HANDLE)p.raw[0], (LPVOID)p.raw[1],
            (LPCVOID)p.raw[2], (SIZE_T)p.raw[3], &written);
        return (DWORD_PTR)(r ? r : TRUE);
    }
    if (n == "ReadProcessMemory") {
        if (no_spawn_ || !p.raw[0]) return (DWORD_PTR)TRUE;
        SIZE_T read = 0;
        BOOL r = ReadProcessMemory(
            (HANDLE)p.raw[0], (LPCVOID)p.raw[1],
            (LPVOID)p.raw[2], (SIZE_T)p.raw[3], &read);
        return (DWORD_PTR)(r ? r : TRUE);
    }

    if (n == "CreateThread") {
        if (no_spawn_) {
            // Return a handle to a suspended dummy thread to satisfy handle-map lookups
            HANDLE h = CreateThread(nullptr, 4096, DummyThreadProc,
                                    nullptr, CREATE_SUSPENDED, nullptr);
            if (!h) {
                // Fallback: duplicate current thread pseudo-handle
                HANDLE dup = nullptr;
                DuplicateHandle(GetCurrentProcess(), GetCurrentThread(),
                                GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS);
                h = dup;
            }
            if (p.raw[5]) *reinterpret_cast<DWORD*>(p.raw[5]) = GetCurrentThreadId();
            return (DWORD_PTR)h;
        }
        return (DWORD_PTR)CreateThread(
            nullptr, (SIZE_T)p.raw[1], DummyThreadProc,
            nullptr, (DWORD)p.raw[4], (LPDWORD)p.raw[5]);
    }
    if (n == "CreateRemoteThread") {
        if (no_spawn_) return (DWORD_PTR)GetCurrentThread();
        return (DWORD_PTR)CreateRemoteThread(
            (HANDLE)p.raw[0], nullptr, (SIZE_T)p.raw[2],
            nullptr, nullptr, (DWORD)p.raw[5], (LPDWORD)p.raw[6]);
    }

    if (n == "QueueUserAPC") {
        // APC function pointer cannot be replayed; succeed silently
        return (DWORD_PTR)TRUE;
    }

    if (n == "NtUnmapViewOfSection") {
        // Allocate a private scratch page, then free it as a stand-in unmap operation.
        // The original section address is not touched.
        void* scratch = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (scratch) VirtualFree(scratch, 0, MEM_RELEASE);
        return 0; // STATUS_SUCCESS
    }

    return 0;
}
