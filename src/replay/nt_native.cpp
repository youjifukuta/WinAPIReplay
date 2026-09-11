#include "replay/nt_native.h"

static NtApi g_nt;

NtApi& GetNtApi() { return g_nt; }

#define LOAD(name) api.name = (PFN_##name)GetProcAddress(h, #name)

void NtApiLoad(NtApi& api) {
    HMODULE h = GetModuleHandleW(L"ntdll.dll");
    if (!h) return;

    // File
    LOAD(NtCreateFile);
    LOAD(NtOpenFile);
    LOAD(NtReadFile);
    LOAD(NtWriteFile);
    LOAD(NtDeleteFile);
    LOAD(NtQueryInformationFile);
    LOAD(NtSetInformationFile);
    // Registry
    LOAD(NtOpenKey);
    LOAD(NtOpenKeyEx);
    LOAD(NtCreateKey);
    LOAD(NtQueryValueKey);
    LOAD(NtSetValueKey);
    LOAD(NtDeleteValueKey);
    LOAD(NtQueryKey);
    LOAD(NtEnumerateKey);
    LOAD(NtEnumerateValueKey);
    LOAD(NtDeleteKey);
    LOAD(NtFlushKey);
    // Memory
    LOAD(NtAllocateVirtualMemory);
    LOAD(NtFreeVirtualMemory);
    LOAD(NtProtectVirtualMemory);
    LOAD(NtCreateSection);
    LOAD(NtOpenSection);
    LOAD(NtMapViewOfSection);
    LOAD(NtUnmapViewOfSection);
    LOAD(NtDuplicateObject);
    // Sync / Handle
    LOAD(NtClose);
    LOAD(NtWaitForSingleObject);
    LOAD(NtCreateMutant);
    LOAD(NtOpenMutant);
    LOAD(NtReleaseMutant);
    LOAD(NtCreateEvent);
    LOAD(NtOpenEvent);
    LOAD(NtSetEvent);
    LOAD(NtResetEvent);
    LOAD(NtCreateSemaphore);
    LOAD(NtOpenSemaphore);
    LOAD(NtCreateTimer);
    LOAD(NtOpenTimer);
    LOAD(NtCreateIoCompletion);
    LOAD(NtOpenIoCompletion);
    LOAD(NtCreateJobObject);
    LOAD(NtOpenJobObject);
    LOAD(NtCreateDebugObject);
    // Loader
    LOAD(LdrLoadDll);
    LOAD(LdrGetDllHandle);
    LOAD(LdrGetDllHandleEx);
    // LdrGetProcedureAddressForCaller → fall back to LdrGetProcedureAddress
    api.LdrGetProcedureAddress = (PFN_LdrGetProcedureAddress)
        GetProcAddress(h, "LdrGetProcedureAddress");
    if (!api.LdrGetProcedureAddress)
        api.LdrGetProcedureAddress = (PFN_LdrGetProcedureAddress)
            GetProcAddress(h, "LdrGetProcedureAddressForCaller");
}

#undef LOAD
