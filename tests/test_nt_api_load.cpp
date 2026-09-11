#include <gtest/gtest.h>
#include "replay/nt_native.h"

// Tests that NtApiLoad() successfully loads all required ntdll function pointers.
// This must pass before any NT executor test can be meaningful.

TEST(NtApiLoad, LoadsFileFunctions) {
    NtApi api{};
    NtApiLoad(api);
    EXPECT_NE(api.NtCreateFile, nullptr);
    EXPECT_NE(api.NtOpenFile, nullptr);
    EXPECT_NE(api.NtReadFile, nullptr);
    EXPECT_NE(api.NtWriteFile, nullptr);
    EXPECT_NE(api.NtDeleteFile, nullptr);
    EXPECT_NE(api.NtQueryInformationFile, nullptr);
    EXPECT_NE(api.NtSetInformationFile, nullptr);
}

TEST(NtApiLoad, LoadsRegistryFunctions) {
    NtApi api{};
    NtApiLoad(api);
    EXPECT_NE(api.NtOpenKey, nullptr);
    EXPECT_NE(api.NtOpenKeyEx, nullptr);
    EXPECT_NE(api.NtCreateKey, nullptr);
    EXPECT_NE(api.NtQueryValueKey, nullptr);
    EXPECT_NE(api.NtSetValueKey, nullptr);
    EXPECT_NE(api.NtDeleteValueKey, nullptr);
    EXPECT_NE(api.NtQueryKey, nullptr);
    EXPECT_NE(api.NtEnumerateKey, nullptr);
    EXPECT_NE(api.NtEnumerateValueKey, nullptr);
    EXPECT_NE(api.NtDeleteKey, nullptr);
    EXPECT_NE(api.NtFlushKey, nullptr);
}

TEST(NtApiLoad, LoadsMemoryFunctions) {
    NtApi api{};
    NtApiLoad(api);
    EXPECT_NE(api.NtAllocateVirtualMemory, nullptr);
    EXPECT_NE(api.NtFreeVirtualMemory, nullptr);
    EXPECT_NE(api.NtProtectVirtualMemory, nullptr);
    EXPECT_NE(api.NtCreateSection, nullptr);
    EXPECT_NE(api.NtOpenSection, nullptr);
    EXPECT_NE(api.NtMapViewOfSection, nullptr);
    EXPECT_NE(api.NtUnmapViewOfSection, nullptr);
    EXPECT_NE(api.NtDuplicateObject, nullptr);
}

TEST(NtApiLoad, LoadsSyncFunctions) {
    NtApi api{};
    NtApiLoad(api);
    EXPECT_NE(api.NtClose, nullptr);
    EXPECT_NE(api.NtWaitForSingleObject, nullptr);
    EXPECT_NE(api.NtCreateMutant, nullptr);
    EXPECT_NE(api.NtOpenMutant, nullptr);
    EXPECT_NE(api.NtReleaseMutant, nullptr);
    EXPECT_NE(api.NtCreateEvent, nullptr);
    EXPECT_NE(api.NtOpenEvent, nullptr);
    EXPECT_NE(api.NtSetEvent, nullptr);
    EXPECT_NE(api.NtResetEvent, nullptr);
    EXPECT_NE(api.NtCreateSemaphore, nullptr);
    EXPECT_NE(api.NtOpenSemaphore, nullptr);
    EXPECT_NE(api.NtCreateTimer, nullptr);
    EXPECT_NE(api.NtCreateIoCompletion, nullptr);
}

TEST(NtApiLoad, LoadsLoaderFunctions) {
    NtApi api{};
    NtApiLoad(api);
    EXPECT_NE(api.LdrLoadDll, nullptr);
    EXPECT_NE(api.LdrGetDllHandle, nullptr);
    EXPECT_NE(api.LdrGetDllHandleEx, nullptr);
    EXPECT_NE(api.LdrGetProcedureAddress, nullptr);
}

TEST(NtApiLoad, GetNtApiIsSingleton) {
    NtApiLoad(GetNtApi());
    EXPECT_EQ(&GetNtApi(), &GetNtApi());
    EXPECT_NE(GetNtApi().NtCreateFile, nullptr);
}

TEST(NtApiLoad, IsIdempotent) {
    // Calling NtApiLoad twice must not crash or clear the pointers.
    NtApi api{};
    NtApiLoad(api);
    auto first = api.NtCreateFile;
    NtApiLoad(api);
    EXPECT_EQ(api.NtCreateFile, first);
}
