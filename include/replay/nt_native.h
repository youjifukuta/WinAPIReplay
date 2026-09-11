#pragma once
// NT native function pointer types and loader.
// All Nt*/Zw*/Ldr* functions are loaded from ntdll.dll at runtime via GetProcAddress
// (ntdll is NOT linked at link time to avoid import-table conflicts).
// Call NtApiLoad() once before the event loop; then call GetNtApi() anywhere.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winternl.h>  // UNICODE_STRING, OBJECT_ATTRIBUTES, IO_STATUS_BLOCK, NT_SUCCESS
#include <string>

// ── Function pointer typedefs ────────────────────────────────────────────────
// All enum parameters are typed as ULONG to avoid redeclaration conflicts.

// File
typedef NTSTATUS (NTAPI *PFN_NtCreateFile)(PHANDLE, ULONG, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *PFN_NtOpenFile)(PHANDLE, ULONG, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
typedef NTSTATUS (NTAPI *PFN_NtReadFile)(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
typedef NTSTATUS (NTAPI *PFN_NtWriteFile)(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
typedef NTSTATUS (NTAPI *PFN_NtDeleteFile)(POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *PFN_NtQueryInformationFile)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG);
typedef NTSTATUS (NTAPI *PFN_NtSetInformationFile)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG);

// Registry
typedef NTSTATUS (NTAPI *PFN_NtOpenKey)(PHANDLE, ULONG, POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *PFN_NtOpenKeyEx)(PHANDLE, ULONG, POBJECT_ATTRIBUTES, ULONG);
typedef NTSTATUS (NTAPI *PFN_NtCreateKey)(PHANDLE, ULONG, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG);
typedef NTSTATUS (NTAPI *PFN_NtQueryValueKey)(HANDLE, PUNICODE_STRING, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *PFN_NtSetValueKey)(HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *PFN_NtDeleteValueKey)(HANDLE, PUNICODE_STRING);
typedef NTSTATUS (NTAPI *PFN_NtQueryKey)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *PFN_NtEnumerateKey)(HANDLE, ULONG, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *PFN_NtEnumerateValueKey)(HANDLE, ULONG, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *PFN_NtDeleteKey)(HANDLE);
typedef NTSTATUS (NTAPI *PFN_NtFlushKey)(HANDLE);

// Memory
typedef NTSTATUS (NTAPI *PFN_NtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *PFN_NtFreeVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG);
typedef NTSTATUS (NTAPI *PFN_NtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *PFN_NtCreateSection)(PHANDLE, ULONG, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS (NTAPI *PFN_NtOpenSection)(PHANDLE, ULONG, POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *PFN_NtMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);
typedef NTSTATUS (NTAPI *PFN_NtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS (NTAPI *PFN_NtDuplicateObject)(HANDLE, HANDLE, HANDLE, PHANDLE, ULONG, ULONG, ULONG);

// Sync / Handle
typedef NTSTATUS (NTAPI *PFN_NtClose)(HANDLE);
typedef NTSTATUS (NTAPI *PFN_NtWaitForSingleObject)(HANDLE, BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS (NTAPI *PFN_NtCreateMutant)(PHANDLE, ULONG, POBJECT_ATTRIBUTES, BOOLEAN);
typedef NTSTATUS (NTAPI *PFN_NtOpenMutant)(PHANDLE, ULONG, POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *PFN_NtReleaseMutant)(HANDLE, PLONG);
typedef NTSTATUS (NTAPI *PFN_NtCreateEvent)(PHANDLE, ULONG, POBJECT_ATTRIBUTES, ULONG, BOOLEAN);
typedef NTSTATUS (NTAPI *PFN_NtOpenEvent)(PHANDLE, ULONG, POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *PFN_NtSetEvent)(HANDLE, PLONG);
typedef NTSTATUS (NTAPI *PFN_NtResetEvent)(HANDLE, PLONG);
typedef NTSTATUS (NTAPI *PFN_NtCreateSemaphore)(PHANDLE, ULONG, POBJECT_ATTRIBUTES, LONG, LONG);
typedef NTSTATUS (NTAPI *PFN_NtOpenSemaphore)(PHANDLE, ULONG, POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *PFN_NtCreateTimer)(PHANDLE, ULONG, POBJECT_ATTRIBUTES, ULONG);
typedef NTSTATUS (NTAPI *PFN_NtOpenTimer)(PHANDLE, ULONG, POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *PFN_NtCreateIoCompletion)(PHANDLE, ULONG, POBJECT_ATTRIBUTES, ULONG);
typedef NTSTATUS (NTAPI *PFN_NtOpenIoCompletion)(PHANDLE, ULONG, POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *PFN_NtCreateJobObject)(PHANDLE, ULONG, POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *PFN_NtOpenJobObject)(PHANDLE, ULONG, POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *PFN_NtCreateDebugObject)(PHANDLE, ULONG, POBJECT_ATTRIBUTES, ULONG);

// Loader
typedef NTSTATUS (NTAPI *PFN_LdrLoadDll)(PWSTR, PULONG, PUNICODE_STRING, PVOID*);
typedef NTSTATUS (NTAPI *PFN_LdrGetDllHandle)(PWSTR, PULONG, PUNICODE_STRING, PVOID*);
typedef NTSTATUS (NTAPI *PFN_LdrGetDllHandleEx)(ULONG, PWSTR, PULONG, PUNICODE_STRING, PVOID*);
// Note: LdrGetProcedureAddressForCaller signature varies; use minimal form.
typedef NTSTATUS (NTAPI *PFN_LdrGetProcedureAddress)(PVOID, PANSI_STRING, ULONG, PVOID*);

// ── NtApi: all loaded function pointers ──────────────────────────────────────

struct NtApi {
    // File
    PFN_NtCreateFile             NtCreateFile             = nullptr;
    PFN_NtOpenFile               NtOpenFile               = nullptr;
    PFN_NtReadFile               NtReadFile               = nullptr;
    PFN_NtWriteFile              NtWriteFile              = nullptr;
    PFN_NtDeleteFile             NtDeleteFile             = nullptr;
    PFN_NtQueryInformationFile   NtQueryInformationFile   = nullptr;
    PFN_NtSetInformationFile     NtSetInformationFile     = nullptr;
    // Registry
    PFN_NtOpenKey                NtOpenKey                = nullptr;
    PFN_NtOpenKeyEx              NtOpenKeyEx              = nullptr;
    PFN_NtCreateKey              NtCreateKey              = nullptr;
    PFN_NtQueryValueKey          NtQueryValueKey          = nullptr;
    PFN_NtSetValueKey            NtSetValueKey            = nullptr;
    PFN_NtDeleteValueKey         NtDeleteValueKey         = nullptr;
    PFN_NtQueryKey               NtQueryKey               = nullptr;
    PFN_NtEnumerateKey           NtEnumerateKey           = nullptr;
    PFN_NtEnumerateValueKey      NtEnumerateValueKey      = nullptr;
    PFN_NtDeleteKey              NtDeleteKey              = nullptr;
    PFN_NtFlushKey               NtFlushKey               = nullptr;
    // Memory
    PFN_NtAllocateVirtualMemory  NtAllocateVirtualMemory  = nullptr;
    PFN_NtFreeVirtualMemory      NtFreeVirtualMemory      = nullptr;
    PFN_NtProtectVirtualMemory   NtProtectVirtualMemory   = nullptr;
    PFN_NtCreateSection          NtCreateSection          = nullptr;
    PFN_NtOpenSection            NtOpenSection            = nullptr;
    PFN_NtMapViewOfSection       NtMapViewOfSection       = nullptr;
    PFN_NtUnmapViewOfSection     NtUnmapViewOfSection     = nullptr;
    PFN_NtDuplicateObject        NtDuplicateObject        = nullptr;
    // Sync / Handle
    PFN_NtClose                  NtClose                  = nullptr;
    PFN_NtWaitForSingleObject    NtWaitForSingleObject    = nullptr;
    PFN_NtCreateMutant           NtCreateMutant           = nullptr;
    PFN_NtOpenMutant             NtOpenMutant             = nullptr;
    PFN_NtReleaseMutant          NtReleaseMutant          = nullptr;
    PFN_NtCreateEvent            NtCreateEvent            = nullptr;
    PFN_NtOpenEvent              NtOpenEvent              = nullptr;
    PFN_NtSetEvent               NtSetEvent               = nullptr;
    PFN_NtResetEvent             NtResetEvent             = nullptr;
    PFN_NtCreateSemaphore        NtCreateSemaphore        = nullptr;
    PFN_NtOpenSemaphore          NtOpenSemaphore          = nullptr;
    PFN_NtCreateTimer            NtCreateTimer            = nullptr;
    PFN_NtOpenTimer              NtOpenTimer              = nullptr;
    PFN_NtCreateIoCompletion     NtCreateIoCompletion     = nullptr;
    PFN_NtOpenIoCompletion       NtOpenIoCompletion       = nullptr;
    PFN_NtCreateJobObject        NtCreateJobObject        = nullptr;
    PFN_NtOpenJobObject          NtOpenJobObject          = nullptr;
    PFN_NtCreateDebugObject      NtCreateDebugObject      = nullptr;
    // Loader
    PFN_LdrLoadDll               LdrLoadDll               = nullptr;
    PFN_LdrGetDllHandle          LdrGetDllHandle          = nullptr;
    PFN_LdrGetDllHandleEx        LdrGetDllHandleEx        = nullptr;
    PFN_LdrGetProcedureAddress   LdrGetProcedureAddress   = nullptr;
};

// Load all function pointers from ntdll.dll.  Idempotent; safe to call multiple times.
void    NtApiLoad(NtApi& api);
NtApi&  GetNtApi();   // returns the process-wide singleton (loaded by NtApiLoad)

// ── NT path helpers ───────────────────────────────────────────────────────────

// Strip NT namespace prefixes (\??\ , \?\ , \\?\) and return the Win32 path.
inline std::wstring NtStripPrefix(const std::wstring& path) {
    static const wchar_t* kPfx[] = { L"\\??\\", L"\\?\\", L"\\\\?\\" };
    for (auto* p : kPfx) {
        size_t n = wcslen(p);
        if (path.size() > n && _wcsnicmp(path.c_str(), p, n) == 0)
            return path.substr(n);
    }
    return path;
}

// Convert Win32 path to NT path (prepend \??\).
inline std::wstring NtMakePath(const std::wstring& win32_path) {
    return L"\\??\\" + win32_path;
}

// Initialise a UNICODE_STRING from a std::wstring that must outlive the struct.
inline void NtInitUnicodeString(UNICODE_STRING& us, const std::wstring& s) {
    us.Buffer        = const_cast<PWSTR>(s.c_str());
    us.Length        = static_cast<USHORT>(s.size() * sizeof(WCHAR));
    us.MaximumLength = us.Length + sizeof(WCHAR);
}

// Build OBJECT_ATTRIBUTES in one call.
inline OBJECT_ATTRIBUTES NtMakeOA(UNICODE_STRING& us, HANDLE root = nullptr) {
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, root, nullptr);
    return oa;
}
