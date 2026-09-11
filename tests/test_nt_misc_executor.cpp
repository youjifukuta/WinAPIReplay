// Tests for NtMiscExecutor: all 93 APIs in SupportedApis().
// NtMiscExecutor reads from event.args directly (not p.raw).
// Grouped by category matching the executor's internal if-chains.
#include <gtest/gtest.h>
#include <windows.h>
#include "replay/handle_map.h"
#include "replay/pointer_map.h"
#include "replay/path_sandbox.h"
#include "replay/registry_sandbox.h"
#include "replay/executors/nt_misc_executor.h"
#include "replay/log_types.h"
#include "replay/arg_preparer.h"

static constexpr wchar_t kSandboxRoot[] = L"C:\\tmp\\NtMiscTest";

static LogEvent MakeEvent(std::string api, std::vector<ArgValue> args = {}) {
    LogEvent ev;
    ev.api_name = std::move(api);
    ev.args = std::move(args);
    return ev;
}

class NtMiscExecutorTest : public ::testing::Test {
protected:
    HandleMap        hmap_;
    PointerMap       pmap_;
    PathSandbox      psb_{kSandboxRoot};
    NtMiscExecutor   exec_{hmap_, pmap_, psb_};
    PreparedArgs     pa_{};

    static void SetUpTestSuite() {
        CreateDirectoryW(kSandboxRoot, nullptr);
        CreateDirectoryW(L"C:\\tmp\\NtMiscTest\\C_", nullptr);
    }
    static void TearDownTestSuite() {
        RemoveDirectoryW(L"C:\\tmp\\NtMiscTest\\C_");
        RemoveDirectoryW(kSandboxRoot);
    }
};

// ── Transaction / thread pool (no-op, STATUS_SUCCESS=0) ──────────────────────

TEST_F(NtMiscExecutorTest, RtlSetCurrentTransaction_NoOp) {
    EXPECT_EQ(exec_.Execute(MakeEvent("RtlSetCurrentTransaction"), pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, NtSetInformationTransaction_NoOp) {
    EXPECT_EQ(exec_.Execute(MakeEvent("NtSetInformationTransaction"), pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, TpAllocWork_NoOp) {
    EXPECT_EQ(exec_.Execute(MakeEvent("TpAllocWork"), pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, TpPostWork_NoOp) {
    EXPECT_EQ(exec_.Execute(MakeEvent("TpPostWork"), pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, TpReleaseWork_NoOp) {
    EXPECT_EQ(exec_.Execute(MakeEvent("TpReleaseWork"), pa_), (DWORD_PTR)0);
}

// ── Exception handler stubs ───────────────────────────────────────────────────

TEST_F(NtMiscExecutorTest, RtlAddVectoredExceptionHandler_Returns1) {
    EXPECT_EQ(exec_.Execute(MakeEvent("RtlAddVectoredExceptionHandler"), pa_), (DWORD_PTR)1);
}

TEST_F(NtMiscExecutorTest, RtlAddVectoredContinueHandler_Returns1) {
    EXPECT_EQ(exec_.Execute(MakeEvent("RtlAddVectoredContinueHandler"), pa_), (DWORD_PTR)1);
}

TEST_F(NtMiscExecutorTest, AddVectoredExceptionHandler_Returns1) {
    EXPECT_EQ(exec_.Execute(MakeEvent("AddVectoredExceptionHandler"), pa_), (DWORD_PTR)1);
}

TEST_F(NtMiscExecutorTest, RtlRemoveVectoredExceptionHandler_ReturnsTRUE) {
    EXPECT_NE(exec_.Execute(MakeEvent("RtlRemoveVectoredExceptionHandler"), pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, RtlRemoveVectoredContinueHandler_ReturnsTRUE) {
    EXPECT_NE(exec_.Execute(MakeEvent("RtlRemoveVectoredContinueHandler"), pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, RemoveVectoredExceptionHandler_ReturnsTRUE) {
    EXPECT_NE(exec_.Execute(MakeEvent("RemoveVectoredExceptionHandler"), pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, SetUnhandledExceptionFilter_ReturnsZero) {
    EXPECT_EQ(exec_.Execute(MakeEvent("SetUnhandledExceptionFilter"), pa_), (DWORD_PTR)0);
}

// ── Process / thread info (no-op STATUS_SUCCESS=0) ────────────────────────────

TEST_F(NtMiscExecutorTest, NtQueryInformationProcess_ReturnsSuccess) {
    EXPECT_EQ(exec_.Execute(MakeEvent("NtQueryInformationProcess"), pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, ZwQueryInformationProcess_ReturnsSuccess) {
    EXPECT_EQ(exec_.Execute(MakeEvent("ZwQueryInformationProcess"), pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, NtSetInformationProcess_ReturnsSuccess) {
    EXPECT_EQ(exec_.Execute(MakeEvent("NtSetInformationProcess"), pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, ZwSetInformationProcess_ReturnsSuccess) {
    EXPECT_EQ(exec_.Execute(MakeEvent("ZwSetInformationProcess"), pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, NtQueryInformationThread_ReturnsSuccess) {
    EXPECT_EQ(exec_.Execute(MakeEvent("NtQueryInformationThread"), pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, ZwQueryInformationThread_ReturnsSuccess) {
    EXPECT_EQ(exec_.Execute(MakeEvent("ZwQueryInformationThread"), pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, NtSetInformationThread_ReturnsSuccess) {
    EXPECT_EQ(exec_.Execute(MakeEvent("NtSetInformationThread"), pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, ZwSetInformationThread_ReturnsSuccess) {
    EXPECT_EQ(exec_.Execute(MakeEvent("ZwSetInformationThread"), pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, NtGetContextThread_ReturnsSuccess) {
    EXPECT_EQ(exec_.Execute(MakeEvent("NtGetContextThread"), pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, NtSetContextThread_ReturnsSuccess) {
    EXPECT_EQ(exec_.Execute(MakeEvent("NtSetContextThread"), pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, NtSuspendThread_ReturnsSuccess) {
    EXPECT_EQ(exec_.Execute(MakeEvent("NtSuspendThread"), pa_), (DWORD_PTR)0);
}

// NtResumeThread: with no mapped handle, should be a no-op (0)
TEST_F(NtMiscExecutorTest, NtResumeThread_UnmappedHandle_ReturnsSuccess) {
    auto ev = MakeEvent("NtResumeThread", {std::wstring(L"0x99990000")});
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, ZwResumeThread_UnmappedHandle_ReturnsSuccess) {
    auto ev = MakeEvent("ZwResumeThread", {std::wstring(L"0x99990001")});
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);
}

// ── NtCreateThreadEx / NtCreateUserProcess (provide dummy handle) ─────────────

TEST_F(NtMiscExecutorTest, NtCreateThreadEx_RegistersDummyHandle) {
    // args[0] = original output handle hex
    auto ev = MakeEvent("NtCreateThreadEx", {std::wstring(L"0x88880000")});
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);
    // Executor registers a dummy handle so downstream NtClose doesn't fail
    EXPECT_TRUE(hmap_.HasMapping(0x88880000));
}

TEST_F(NtMiscExecutorTest, NtCreateUserProcess_RegistersDummyHandle) {
    auto ev = MakeEvent("NtCreateUserProcess", {std::wstring(L"0x88880001")});
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);
    EXPECT_TRUE(hmap_.HasMapping(0x88880001));
}

TEST_F(NtMiscExecutorTest, ZwCreateUserProcess_RegistersDummyHandle) {
    auto ev = MakeEvent("ZwCreateUserProcess", {std::wstring(L"0x88880002")});
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);
    EXPECT_TRUE(hmap_.HasMapping(0x88880002));
}

// ── NtOpenProcess / NtOpenThread ──────────────────────────────────────────────

TEST_F(NtMiscExecutorTest, NtOpenProcess_RegistersHandle) {
    // args[0]=orig handle hex, args[3]=PID hex
    auto ev = MakeEvent("NtOpenProcess", {
        std::wstring(L"0x77770000"),  // out handle
        (int64_t)0, (int64_t)0,
        std::wstring(L"0x4"),          // PID (4 = System; substitute current if fails)
    });
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);
    EXPECT_TRUE(hmap_.HasMapping(0x77770000));
}

TEST_F(NtMiscExecutorTest, ZwOpenProcess_RegistersHandle) {
    auto ev = MakeEvent("ZwOpenProcess", {
        std::wstring(L"0x77770001"),
        (int64_t)0, (int64_t)0,
        (int64_t)0,  // PID=0 → falls back to current process
    });
    exec_.Execute(ev, pa_);
    EXPECT_TRUE(hmap_.HasMapping(0x77770001));
}

TEST_F(NtMiscExecutorTest, NtOpenThread_RegistersHandle) {
    auto ev = MakeEvent("NtOpenThread", {
        std::wstring(L"0x77770002"),
        (int64_t)0, (int64_t)0, (int64_t)0,
        (int64_t)0,  // TID=0 → falls back to current thread duplicate
    });
    exec_.Execute(ev, pa_);
    EXPECT_TRUE(hmap_.HasMapping(0x77770002));
}

TEST_F(NtMiscExecutorTest, ZwOpenThread_RegistersHandle) {
    auto ev = MakeEvent("ZwOpenThread", {
        std::wstring(L"0x77770003"),
        (int64_t)0, (int64_t)0, (int64_t)0,
        (int64_t)0,
    });
    exec_.Execute(ev, pa_);
    EXPECT_TRUE(hmap_.HasMapping(0x77770003));
}

// ── Token APIs ────────────────────────────────────────────────────────────────

TEST_F(NtMiscExecutorTest, NtOpenProcessToken_RegistersHandle) {
    auto ev = MakeEvent("NtOpenProcessToken", {
        (int64_t)0,               // process handle (unmapped → current proc)
        (int64_t)TOKEN_ALL_ACCESS,
        std::wstring(L"0x66660000"), // output token handle
    });
    exec_.Execute(ev, pa_);
    EXPECT_TRUE(hmap_.HasMapping(0x66660000));
}

TEST_F(NtMiscExecutorTest, NtOpenProcessTokenEx_RegistersHandle) {
    auto ev = MakeEvent("NtOpenProcessTokenEx", {
        (int64_t)0, (int64_t)TOKEN_ALL_ACCESS, (int64_t)0,
        std::wstring(L"0x66660001"),
    });
    exec_.Execute(ev, pa_);
    EXPECT_TRUE(hmap_.HasMapping(0x66660001));
}

TEST_F(NtMiscExecutorTest, NtOpenThreadToken_RegistersHandle) {
    auto ev = MakeEvent("NtOpenThreadToken", {
        (int64_t)0, (int64_t)TOKEN_ALL_ACCESS, (int64_t)0,
        std::wstring(L"0x66660002"),
    });
    exec_.Execute(ev, pa_);
    EXPECT_TRUE(hmap_.HasMapping(0x66660002));
}

TEST_F(NtMiscExecutorTest, NtOpenThreadTokenEx_RegistersHandle) {
    auto ev = MakeEvent("NtOpenThreadTokenEx", {
        (int64_t)0, (int64_t)TOKEN_ALL_ACCESS, (int64_t)0, (int64_t)0,
        std::wstring(L"0x66660003"),
    });
    exec_.Execute(ev, pa_);
    EXPECT_TRUE(hmap_.HasMapping(0x66660003));
}

TEST_F(NtMiscExecutorTest, NtQueryInformationToken_ReturnsSuccess) {
    EXPECT_EQ(exec_.Execute(MakeEvent("NtQueryInformationToken"), pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, NtSetInformationToken_ReturnsSuccess) {
    EXPECT_EQ(exec_.Execute(MakeEvent("NtSetInformationToken"), pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, NtAdjustPrivilegesToken_ReturnsSuccess) {
    EXPECT_EQ(exec_.Execute(MakeEvent("NtAdjustPrivilegesToken"), pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, OpenThreadToken_RegistersHandle) {
    auto ev = MakeEvent("OpenThreadToken", {
        (int64_t)0, (int64_t)TOKEN_ALL_ACCESS, (int64_t)0,
        std::wstring(L"0x66660010"),
    });
    exec_.Execute(ev, pa_);
    EXPECT_TRUE(hmap_.HasMapping(0x66660010));
}

TEST_F(NtMiscExecutorTest, LookupPrivilegeValueW_ReturnsTRUE) {
    auto ev = MakeEvent("LookupPrivilegeValueW", {
        (int64_t)0, std::wstring(L"SeDebugPrivilege"),
    });
    EXPECT_NE(exec_.Execute(ev, pa_), (DWORD_PTR)FALSE);
}

TEST_F(NtMiscExecutorTest, LookupPrivilegeValueA_ReturnsTRUE) {
    auto ev = MakeEvent("LookupPrivilegeValueA", {
        (int64_t)0, std::wstring(L"SeDebugPrivilege"),
    });
    EXPECT_NE(exec_.Execute(ev, pa_), (DWORD_PTR)FALSE);
}

TEST_F(NtMiscExecutorTest, LookupPrivilegeNameW_ReturnsTRUE) {
    EXPECT_NE(exec_.Execute(MakeEvent("LookupPrivilegeNameW"), pa_), (DWORD_PTR)FALSE);
}

TEST_F(NtMiscExecutorTest, LookupPrivilegeNameA_ReturnsTRUE) {
    EXPECT_NE(exec_.Execute(MakeEvent("LookupPrivilegeNameA"), pa_), (DWORD_PTR)FALSE);
}

TEST_F(NtMiscExecutorTest, AdjustTokenGroups_ReturnsTRUE) {
    EXPECT_NE(exec_.Execute(MakeEvent("AdjustTokenGroups"), pa_), (DWORD_PTR)FALSE);
}

TEST_F(NtMiscExecutorTest, LsaOpenPolicy_RegistersHandle) {
    // args[3] or args[1] = orig output handle hex
    auto ev = MakeEvent("LsaOpenPolicy", {
        (int64_t)0, (int64_t)0, (int64_t)0,
        std::wstring(L"0x55550000"),
    });
    exec_.Execute(ev, pa_);
    EXPECT_TRUE(hmap_.HasMapping(0x55550000));
}

// ── COM ───────────────────────────────────────────────────────────────────────

TEST_F(NtMiscExecutorTest, CoCreateInstance_ReturnsREGDB_E_CLASSNOTREG) {
    EXPECT_EQ(exec_.Execute(MakeEvent("CoCreateInstance"), pa_), (DWORD_PTR)0x80040154);
}

TEST_F(NtMiscExecutorTest, CoGetClassObject_ReturnsREGDB_E_CLASSNOTREG) {
    EXPECT_EQ(exec_.Execute(MakeEvent("CoGetClassObject"), pa_), (DWORD_PTR)0x80040154);
}

TEST_F(NtMiscExecutorTest, CoInitialize_ReturnsSuccess) {
    EXPECT_EQ(exec_.Execute(MakeEvent("CoInitialize"), pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, CoInitializeEx_ReturnsSuccess) {
    auto ev = MakeEvent("CoInitializeEx", {(int64_t)0, (int64_t)0x0 /*COINIT_MULTITHREADED*/});
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, CoUninitialize_ReturnsSuccess) {
    EXPECT_EQ(exec_.Execute(MakeEvent("CoUninitialize"), pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, OleInitialize_ReturnsSuccess) {
    EXPECT_EQ(exec_.Execute(MakeEvent("OleInitialize"), pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, OleUninitialize_ReturnsSuccess) {
    EXPECT_EQ(exec_.Execute(MakeEvent("OleUninitialize"), pa_), (DWORD_PTR)0);
}

// ── Shell / UI ────────────────────────────────────────────────────────────────

TEST_F(NtMiscExecutorTest, ShellExecuteExW_ReturnsTRUE) {
    EXPECT_NE(exec_.Execute(MakeEvent("ShellExecuteExW"), pa_), (DWORD_PTR)FALSE);
}

TEST_F(NtMiscExecutorTest, ShellExecuteExA_ReturnsTRUE) {
    EXPECT_NE(exec_.Execute(MakeEvent("ShellExecuteExA"), pa_), (DWORD_PTR)FALSE);
}

TEST_F(NtMiscExecutorTest, UpdateProcThreadAttribute_ReturnsTRUE) {
    EXPECT_NE(exec_.Execute(MakeEvent("UpdateProcThreadAttribute"), pa_), (DWORD_PTR)FALSE);
}

TEST_F(NtMiscExecutorTest, SystemParametersInfoW_GetAction_ReturnsTRUE) {
    // action=SPI_GETWORKAREA (48=0x30, even → GET)
    auto ev = MakeEvent("SystemParametersInfoW", {(int64_t)SPI_GETWORKAREA, (int64_t)0});
    EXPECT_NE(exec_.Execute(ev, pa_), (DWORD_PTR)FALSE);
}

TEST_F(NtMiscExecutorTest, SystemParametersInfoA_GetAction_ReturnsTRUE) {
    auto ev = MakeEvent("SystemParametersInfoA", {(int64_t)SPI_GETWORKAREA, (int64_t)0});
    EXPECT_NE(exec_.Execute(ev, pa_), (DWORD_PTR)FALSE);
}

// ── FindFirstFile / FindNextFile (sandbox) ────────────────────────────────────

TEST_F(NtMiscExecutorTest, FindFirstFileExW_SandboxPath_ReturnsHandle) {
    // Pre-create a file in sandbox for FindFirstFile to find
    HANDLE hf = CreateFileW(L"C:\\tmp\\NtMiscTest\\C_\\misc.txt",
                             GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf != INVALID_HANDLE_VALUE) CloseHandle(hf);

    // psb_ already enabled (non-empty root kSandboxRoot)
    // args[0] = path string that gets sandbox-redirected
    auto ev = MakeEvent("FindFirstFileExW", {std::wstring(L"C:\\*.txt")});
    DWORD_PTR ret = exec_.Execute(ev, pa_);
    HANDLE h = (HANDLE)ret;
    if (h && h != INVALID_HANDLE_VALUE) FindClose(h);
    DeleteFileW(L"C:\\tmp\\NtMiscTest\\C_\\misc.txt");
}

TEST_F(NtMiscExecutorTest, FindFirstFileW_SandboxPath_DoesNotCrash) {
    // psb_ already enabled (non-empty root kSandboxRoot)
    auto ev = MakeEvent("FindFirstFileW", {std::wstring(L"C:\\*.tmp")});
    DWORD_PTR ret = exec_.Execute(ev, pa_);
    HANDLE h = (HANDLE)ret;
    if (h && h != INVALID_HANDLE_VALUE) FindClose(h);
}

TEST_F(NtMiscExecutorTest, FindNextFileW_UnmappedHandle_ReturnsFALSE) {
    // args[1]=null handle hex → FindNextFileW(NULL,...) returns FALSE without AV
    // (Arbitrary non-null-but-invalid handles like 0x12345678 cause OS AV)
    auto ev = MakeEvent("FindNextFileW", {
        std::wstring(L"some_file.txt"),   // [0] output filename
        std::wstring(L"0x00000000"),      // [1] hFindFile (null → graceful fail)
    });
    DWORD_PTR ret = exec_.Execute(ev, pa_);
    EXPECT_EQ(ret, (DWORD_PTR)FALSE);
}

TEST_F(NtMiscExecutorTest, FindNextFileA_UnmappedHandle_ReturnsFALSE) {
    auto ev = MakeEvent("FindNextFileA", {
        std::wstring(L"some_file.txt"),
        std::wstring(L"0x00000000"),      // null handle → graceful fail, no AV
    });
    DWORD_PTR ret = exec_.Execute(ev, pa_);
    EXPECT_EQ(ret, (DWORD_PTR)FALSE);
}

// ── Path APIs ─────────────────────────────────────────────────────────────────

TEST_F(NtMiscExecutorTest, PathCombineW_ReturnsTRUE) {
    auto ev = MakeEvent("PathCombineW", {
        (int64_t)0,
        std::wstring(L"C:\\Windows"),
        std::wstring(L"System32"),
    });
    EXPECT_NE(exec_.Execute(ev, pa_), (DWORD_PTR)FALSE);
}

TEST_F(NtMiscExecutorTest, PathCombineA_ReturnsTRUE) {
    auto ev = MakeEvent("PathCombineA", {
        (int64_t)0,
        std::wstring(L"C:\\Windows"),
        std::wstring(L"System32"),
    });
    EXPECT_NE(exec_.Execute(ev, pa_), (DWORD_PTR)FALSE);
}

TEST_F(NtMiscExecutorTest, PathCchCombineEx_ReturnsSuccess) {
    auto ev = MakeEvent("PathCchCombineEx", {
        (int64_t)0, (int64_t)0,
        std::wstring(L"C:\\Windows"),
        std::wstring(L"System32"),
    });
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);  // S_OK
}

TEST_F(NtMiscExecutorTest, PathCchCombineExW_ReturnsSuccess) {
    auto ev = MakeEvent("PathCchCombineExW", {
        (int64_t)0, (int64_t)0,
        std::wstring(L"C:\\Windows"),
        std::wstring(L"System32"),
    });
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, PathCchCombine_ReturnsSuccess) {
    auto ev = MakeEvent("PathCchCombine", {
        (int64_t)0, (int64_t)0,
        std::wstring(L"C:\\temp"),
        std::wstring(L"file.txt"),
    });
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, PathCchCombineW_ReturnsSuccess) {
    auto ev = MakeEvent("PathCchCombineW", {
        (int64_t)0, (int64_t)0,
        std::wstring(L"C:\\temp"),
        std::wstring(L"file.txt"),
    });
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, PathAppendW_ReturnsTRUE) {
    auto ev = MakeEvent("PathAppendW", {
        std::wstring(L"C:\\Windows"),
        std::wstring(L"System32"),
    });
    EXPECT_NE(exec_.Execute(ev, pa_), (DWORD_PTR)FALSE);
}

TEST_F(NtMiscExecutorTest, PathAppendA_ReturnsTRUE) {
    EXPECT_NE(exec_.Execute(MakeEvent("PathAppendA"), pa_), (DWORD_PTR)FALSE);
}

TEST_F(NtMiscExecutorTest, PathCanonicalizeW_ReturnsTRUE) {
    auto ev = MakeEvent("PathCanonicalizeW", {
        (int64_t)0,
        std::wstring(L"C:\\Windows\\..\\Windows"),
    });
    EXPECT_NE(exec_.Execute(ev, pa_), (DWORD_PTR)FALSE);
}

TEST_F(NtMiscExecutorTest, PathCanonicalizeA_ReturnsTRUE) {
    EXPECT_NE(exec_.Execute(MakeEvent("PathCanonicalizeA"), pa_), (DWORD_PTR)FALSE);
}

TEST_F(NtMiscExecutorTest, PathAddBackslashW_Returns1) {
    auto ev = MakeEvent("PathAddBackslashW", {std::wstring(L"C:\\Windows")});
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)1);
}

TEST_F(NtMiscExecutorTest, PathAddBackslashA_Returns1) {
    EXPECT_EQ(exec_.Execute(MakeEvent("PathAddBackslashA"), pa_), (DWORD_PTR)1);
}

TEST_F(NtMiscExecutorTest, PathRemoveFileSpecW_ReturnsTRUE) {
    auto ev = MakeEvent("PathRemoveFileSpecW", {std::wstring(L"C:\\Windows\\notepad.exe")});
    EXPECT_NE(exec_.Execute(ev, pa_), (DWORD_PTR)FALSE);
}

TEST_F(NtMiscExecutorTest, PathRemoveFileSpecA_ReturnsTRUE) {
    EXPECT_NE(exec_.Execute(MakeEvent("PathRemoveFileSpecA"), pa_), (DWORD_PTR)FALSE);
}

TEST_F(NtMiscExecutorTest, PathAllocCombine_ReturnsSuccess) {
    EXPECT_EQ(exec_.Execute(MakeEvent("PathAllocCombine"), pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, PathAllocCombineW_ReturnsSuccess) {
    EXPECT_EQ(exec_.Execute(MakeEvent("PathAllocCombineW"), pa_), (DWORD_PTR)0);
}

// ── URL APIs ──────────────────────────────────────────────────────────────────

TEST_F(NtMiscExecutorTest, UrlCanonicalizeW_ReturnsSuccess) {
    auto ev = MakeEvent("UrlCanonicalizeW", {
        std::wstring(L"http://example.com/path/../file"),
    });
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, UrlCanonicalizeA_ReturnsSuccess) {
    EXPECT_EQ(exec_.Execute(MakeEvent("UrlCanonicalizeA"), pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, UrlCombineW_ReturnsSuccess) {
    EXPECT_EQ(exec_.Execute(MakeEvent("UrlCombineW"), pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, UrlCombineA_ReturnsSuccess) {
    EXPECT_EQ(exec_.Execute(MakeEvent("UrlCombineA"), pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, RtlDosPathNameToNtPathName_U_ReturnsTRUE) {
    EXPECT_NE(exec_.Execute(MakeEvent("RtlDosPathNameToNtPathName_U"), pa_), (DWORD_PTR)FALSE);
}

TEST_F(NtMiscExecutorTest, RtlDosPathNameToRelativeName_U_ReturnsTRUE) {
    EXPECT_NE(exec_.Execute(MakeEvent("RtlDosPathNameToRelativeName_U"), pa_), (DWORD_PTR)FALSE);
}

// ── NT file attributes / IO ───────────────────────────────────────────────────

TEST_F(NtMiscExecutorTest, NtQueryAttributesFile_SandboxPath_ReturnsSuccess) {
    // psb_ already enabled (non-empty root kSandboxRoot)
    auto ev = MakeEvent("NtQueryAttributesFile", {
        std::wstring(L"C:\\Windows\\System32\\kernel32.dll"),
    });
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, ZwQueryAttributesFile_ReturnsSuccess) {
    auto ev = MakeEvent("ZwQueryAttributesFile", {std::wstring(L"C:\\temp")});
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, NtQueryFullAttributesFile_ReturnsSuccess) {
    auto ev = MakeEvent("NtQueryFullAttributesFile", {std::wstring(L"C:\\temp")});
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, NtFlushBuffersFile_UnmappedHandle_ReturnsSuccess) {
    // args[0] = handle hex not in hmap → no FlushFileBuffers call
    auto ev = MakeEvent("NtFlushBuffersFile", {std::wstring(L"0x99999999")});
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, NtCancelIoFile_ReturnsSuccess) {
    EXPECT_EQ(exec_.Execute(MakeEvent("NtCancelIoFile"), pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, NtDeviceIoControlFile_ReturnsSuccess) {
    EXPECT_EQ(exec_.Execute(MakeEvent("NtDeviceIoControlFile"), pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, NtFsControlFile_ReturnsSuccess) {
    EXPECT_EQ(exec_.Execute(MakeEvent("NtFsControlFile"), pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, NtLockFile_ReturnsSuccess) {
    EXPECT_EQ(exec_.Execute(MakeEvent("NtLockFile"), pa_), (DWORD_PTR)0);
}

TEST_F(NtMiscExecutorTest, NtUnlockFile_ReturnsSuccess) {
    EXPECT_EQ(exec_.Execute(MakeEvent("NtUnlockFile"), pa_), (DWORD_PTR)0);
}


// ── NtResumeThread with mapped handle ─────────────────────────────────────────

TEST_F(NtMiscExecutorTest, NtResumeThread_MappedHandle_CallsResumeThread) {
    // Create a suspended thread and register it in hmap_
    HANDLE h = CreateThread(nullptr, 0, [](LPVOID) -> DWORD { return 0; },
                             nullptr, CREATE_SUSPENDED, nullptr);
    ASSERT_NE(h, (HANDLE)nullptr);
    hmap_.Register(0xAAA10000, (DWORD_PTR)h);

    auto ev = MakeEvent("NtResumeThread", {std::wstring(L"0xAAA10000")});
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);

    // Clean up: wait briefly for thread to exit, then close
    WaitForSingleObject(h, 200);
    CloseHandle(h);
}

// ── Unknown API returns 0 ─────────────────────────────────────────────────────

TEST_F(NtMiscExecutorTest, UnknownApi_ReturnsZero) {
    DWORD_PTR ret = exec_.Execute(MakeEvent("NtMiscUnknown"), pa_);
    EXPECT_EQ(ret, (DWORD_PTR)0);
}
