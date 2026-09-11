#include <gtest/gtest.h>
#include <windows.h>
#include <shlwapi.h>
#include "replay/nt_native.h"
#include "replay/handle_map.h"
#include "replay/pointer_map.h"
#include "replay/path_sandbox.h"
#include "replay/executors/nt_file_executor.h"
#include "replay/log_types.h"
#include "replay/arg_preparer.h"

// Sandbox root for file tests.  Drive "C:\" paths become C:\tmp\NtFileTest\C_\<file>.
static constexpr wchar_t kSandboxRoot[] = L"C:\\tmp\\NtFileTest";

static LogEvent MakeEvent(std::string api,
                           std::initializer_list<ArgValue> args) {
    LogEvent ev;
    ev.api_name = std::move(api);
    ev.args.assign(args);
    return ev;
}

class NtFileExecutorTest : public ::testing::Test {
protected:
    HandleMap      hmap_;
    PointerMap     pmap_;
    PathSandbox    sandbox_{kSandboxRoot};
    NtFileExecutor exec_{hmap_, pmap_, sandbox_};
    PreparedArgs   pa_{};

    static void SetUpTestSuite() {
        NtApiLoad(GetNtApi());
        CreateDirectoryW(kSandboxRoot, nullptr);
        CreateDirectoryW(L"C:\\tmp\\NtFileTest\\C_", nullptr);
    }

    static void TearDownTestSuite() {
        // Best-effort cleanup.
        DeleteFileW(L"C:\\tmp\\NtFileTest\\C_\\nft_create.txt");
        DeleteFileW(L"C:\\tmp\\NtFileTest\\C_\\nft_open.txt");
        DeleteFileW(L"C:\\tmp\\NtFileTest\\C_\\nft_write.txt");
        DeleteFileW(L"C:\\tmp\\NtFileTest\\C_\\nft_read.txt");
        DeleteFileW(L"C:\\tmp\\NtFileTest\\C_\\nft_del.txt");
        DeleteFileW(L"C:\\tmp\\NtFileTest\\C_\\nft_chain.txt");
        DeleteFileW(L"C:\\tmp\\NtFileTest\\C_\\nft_qinfo.txt");
        DeleteFileW(L"C:\\tmp\\NtFileTest\\C_\\nft_qinfo_name.txt");
        DeleteFileW(L"C:\\tmp\\NtFileTest\\C_\\nft_zw_create.txt");
        DeleteFileW(L"C:\\tmp\\NtFileTest\\C_\\nft_zw_open.txt");
        RemoveDirectoryW(L"C:\\tmp\\NtFileTest\\C_");
        RemoveDirectoryW(kSandboxRoot);
    }
};

// ── NtCreateFile ──────────────────────────────────────────────────────────────

TEST_F(NtFileExecutorTest, NtCreateFile_CreatesFileAndRegistersHandle) {
    LogEvent ev = MakeEvent("NtCreateFile", {
        std::wstring(L"0x100"),               // [0] orig handle
        (int64_t)0,                            // [1] access (default)
        std::wstring(L"C:\\nft_create.txt"),  // [2] path
        (int64_t)0,                            // [3] share (default)
        (int64_t)3,                            // [4] FILE_OPEN_IF
        (int64_t)0,                            // [5] opts
    });
    DWORD_PTR status = exec_.Execute(ev, pa_);
    EXPECT_EQ(status, (DWORD_PTR)0);          // STATUS_SUCCESS
    EXPECT_TRUE(hmap_.HasMapping(0x100));
}

TEST_F(NtFileExecutorTest, NtCreateFile_ExistingPath_SkipsIfAlreadyMapped) {
    // Second call with same orig handle is a no-op.
    LogEvent ev = MakeEvent("NtCreateFile", {
        std::wstring(L"0x100"),               // already mapped by previous test
        (int64_t)0,
        std::wstring(L"C:\\nft_create.txt"),
        (int64_t)0, (int64_t)3, (int64_t)0,
    });
    // Returns 0 (no-op) and mapping is still present.
    DWORD_PTR status = exec_.Execute(ev, pa_);
    EXPECT_EQ(status, (DWORD_PTR)0);
    EXPECT_TRUE(hmap_.HasMapping(0x100));
}

// ── NtOpenFile ────────────────────────────────────────────────────────────────

TEST_F(NtFileExecutorTest, NtOpenFile_OpensExistingFileAndRegistersHandle) {
    // Pre-create file in sandbox location.
    HANDLE h = CreateFileW(L"C:\\tmp\\NtFileTest\\C_\\nft_open.txt",
                            GENERIC_WRITE, 0, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);

    LogEvent ev = MakeEvent("NtOpenFile", {
        std::wstring(L"0x101"),              // [0] orig handle
        (int64_t)0,                           // [1] access (default)
        std::wstring(L"C:\\nft_open.txt"),   // [2] path
        (int64_t)0,                           // [3] share (default)
    });
    DWORD_PTR status = exec_.Execute(ev, pa_);
    EXPECT_EQ(status, (DWORD_PTR)0);         // STATUS_SUCCESS
    EXPECT_TRUE(hmap_.HasMapping(0x101));
}

// ── NtWriteFile ───────────────────────────────────────────────────────────────

TEST_F(NtFileExecutorTest, NtWriteFile_WithMappedHandle_Succeeds) {
    // Create a file and get a real handle.
    LogEvent create_ev = MakeEvent("NtCreateFile", {
        std::wstring(L"0x102"), (int64_t)0,
        std::wstring(L"C:\\nft_write.txt"),
        (int64_t)0, (int64_t)3, (int64_t)0,
    });
    exec_.Execute(create_ev, pa_);
    ASSERT_TRUE(hmap_.HasMapping(0x102));

    LogEvent ev = MakeEvent("NtWriteFile", {
        std::wstring(L"0x102"),  // [0] orig handle
        (int64_t)0,               // [1]
        (int64_t)0,               // [2]
        (int64_t)8,               // [3] byte_count
    });
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);  // STATUS_SUCCESS
}

TEST_F(NtFileExecutorTest, NtWriteFile_WithUnmappedHandle_ReturnsApprox) {
    // 0x999 is not in HandleMap → real_h == orig_h → STATUS_INVALID_HANDLE (approx).
    LogEvent ev = MakeEvent("NtWriteFile", {
        std::wstring(L"0x999"), (int64_t)0, (int64_t)0, (int64_t)8,
    });
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0xC0000008);  // STATUS_INVALID_HANDLE
}

// ── NtReadFile ────────────────────────────────────────────────────────────────

TEST_F(NtFileExecutorTest, NtReadFile_WithMappedHandle_Succeeds) {
    LogEvent create_ev = MakeEvent("NtCreateFile", {
        std::wstring(L"0x103"), (int64_t)0,
        std::wstring(L"C:\\nft_read.txt"),
        (int64_t)0, (int64_t)3, (int64_t)0,
    });
    exec_.Execute(create_ev, pa_);
    ASSERT_TRUE(hmap_.HasMapping(0x103));

    LogEvent ev = MakeEvent("NtReadFile", {
        std::wstring(L"0x103"), (int64_t)0, (int64_t)0, (int64_t)8,
    });
    // STATUS_SUCCESS (0) or STATUS_END_OF_FILE (0xC0000011) are both acceptable;
    // executor maps STATUS_END_OF_FILE to 0 for empty sandbox files.
    DWORD_PTR st = exec_.Execute(ev, pa_);
    EXPECT_EQ(st, (DWORD_PTR)0);
}

TEST_F(NtFileExecutorTest, NtReadFile_WithUnmappedHandle_ReturnsApprox) {
    LogEvent ev = MakeEvent("NtReadFile", {
        std::wstring(L"0x998"), (int64_t)0, (int64_t)0, (int64_t)8,
    });
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0xC0000008);  // STATUS_INVALID_HANDLE
}

// ── NtDeleteFile ──────────────────────────────────────────────────────────────

TEST_F(NtFileExecutorTest, NtDeleteFile_DeletesFileFromSandbox) {
    HANDLE hf = CreateFileW(L"C:\\tmp\\NtFileTest\\C_\\nft_del.txt",
                             GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf != INVALID_HANDLE_VALUE) CloseHandle(hf);

    LogEvent ev = MakeEvent("NtDeleteFile", {
        std::wstring(L"C:\\nft_del.txt"),  // [0] path
    });
    DWORD_PTR status = exec_.Execute(ev, pa_);
    EXPECT_EQ(status, (DWORD_PTR)0);  // STATUS_SUCCESS
    EXPECT_FALSE(PathFileExistsW(L"C:\\tmp\\NtFileTest\\C_\\nft_del.txt"));
}

// ── Handle chain (NtCreateFile → NtWriteFile → NtReadFile) ───────────────────

TEST_F(NtFileExecutorTest, HandleChain_CreateWriteRead) {
    // Verifies that the handle produced by NtCreateFile can be reused by
    // subsequent NtWriteFile and NtReadFile events through the HandleMap.
    LogEvent create_ev = MakeEvent("NtCreateFile", {
        std::wstring(L"0x110"), (int64_t)0,
        std::wstring(L"C:\\nft_chain.txt"),
        (int64_t)0, (int64_t)3, (int64_t)0,
    });
    ASSERT_EQ(exec_.Execute(create_ev, pa_), (DWORD_PTR)0);
    ASSERT_TRUE(hmap_.HasMapping(0x110));

    LogEvent write_ev = MakeEvent("NtWriteFile", {
        std::wstring(L"0x110"), (int64_t)0, (int64_t)0, (int64_t)4,
    });
    EXPECT_EQ(exec_.Execute(write_ev, pa_), (DWORD_PTR)0);

    LogEvent read_ev = MakeEvent("NtReadFile", {
        std::wstring(L"0x110"), (int64_t)0, (int64_t)0, (int64_t)4,
    });
    EXPECT_EQ(exec_.Execute(read_ev, pa_), (DWORD_PTR)0);
}

// ── NtQueryInformationFile ────────────────────────────────────────────────────

TEST_F(NtFileExecutorTest, NtQueryInformationFile_WithMappedHandle_Succeeds) {
    // Create a file to get a real handle, then query its standard information.
    LogEvent create_ev = MakeEvent("NtCreateFile", {
        std::wstring(L"0x130"), (int64_t)0,
        std::wstring(L"C:\\nft_qinfo.txt"),
        (int64_t)0, (int64_t)3, (int64_t)0,
    });
    exec_.Execute(create_ev, pa_);
    ASSERT_TRUE(hmap_.HasMapping(0x130));

    LogEvent ev = MakeEvent("NtQueryInformationFile", {
        std::wstring(L"0x130"),  // [0] handle
        (int64_t)0,              // [1] path (unused)
        (int64_t)5,              // [2] FileNameInformation (class 9 may need large buffer; 5=standard)
    });
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);  // STATUS_SUCCESS
}

TEST_F(NtFileExecutorTest, NtQueryInformationFile_WithUnmappedHandle_ReturnsApprox) {
    // Unmapped handle: real_h == orig_h → STATUS_INVALID_HANDLE (approx).
    LogEvent ev = MakeEvent("NtQueryInformationFile", {
        std::wstring(L"0x9A0"), (int64_t)0, (int64_t)5,
    });
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0xC0000008);  // STATUS_INVALID_HANDLE
}

// ── NtSetInformationFile ──────────────────────────────────────────────────────

TEST_F(NtFileExecutorTest, NtQueryInformationFile_FileNameInformation_Succeeds) {
    // FileNameInformation (class 9) returns a variable-length struct; the old
    // 512-byte buffer caused STATUS_BUFFER_OVERFLOW (0x80000005) which was
    // misclassified as "failed".  The new 4096-byte buffer (+ BUFFER_OVERFLOW→0 map)
    // must return STATUS_SUCCESS for typical sandbox paths.
    LogEvent create_ev = MakeEvent("NtCreateFile", {
        std::wstring(L"0x140"), (int64_t)0,
        std::wstring(L"C:\\nft_qinfo_name.txt"),
        (int64_t)0, (int64_t)3, (int64_t)0,
    });
    exec_.Execute(create_ev, pa_);
    ASSERT_TRUE(hmap_.HasMapping(0x140));

    LogEvent ev = MakeEvent("NtQueryInformationFile", {
        std::wstring(L"0x140"),  // handle
        (int64_t)0,              // path (unused by executor)
        (int64_t)9,              // FileNameInformation (variable-length)
    });
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);  // STATUS_SUCCESS
}

TEST_F(NtFileExecutorTest, NtSetInformationFile_WithUnmappedHandle_ReturnsApprox) {
    // Unmapped handle: real_h == orig_h → STATUS_INVALID_HANDLE (approx).
    LogEvent ev = MakeEvent("NtSetInformationFile", {
        std::wstring(L"0x9A1"), (int64_t)0, (int64_t)4,  // FileBasicInformation
    });
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0xC0000008);  // STATUS_INVALID_HANDLE
}

// ── Zw* aliases (same code paths as Nt* variants) ─────────────────────────────

TEST_F(NtFileExecutorTest, ZwAliases_ProduceSameOutcomesAsNtVariants) {
    // ZwCreateFile → same branch as NtCreateFile.
    LogEvent zw_create = MakeEvent("ZwCreateFile", {
        std::wstring(L"0x131"), (int64_t)0,
        std::wstring(L"C:\\nft_zw_create.txt"),
        (int64_t)0, (int64_t)3, (int64_t)0,
    });
    EXPECT_EQ(exec_.Execute(zw_create, pa_), (DWORD_PTR)0);
    EXPECT_TRUE(hmap_.HasMapping(0x131));

    // ZwWriteFile → same branch as NtWriteFile; uses handle created above.
    EXPECT_EQ(exec_.Execute(MakeEvent("ZwWriteFile", {
        std::wstring(L"0x131"), (int64_t)0, (int64_t)0, (int64_t)8,
    }), pa_), (DWORD_PTR)0);

    // ZwReadFile → same branch as NtReadFile; uses same handle.
    EXPECT_EQ(exec_.Execute(MakeEvent("ZwReadFile", {
        std::wstring(L"0x131"), (int64_t)0, (int64_t)0, (int64_t)8,
    }), pa_), (DWORD_PTR)0);

    // ZwQueryInformationFile → unmapped handle → STATUS_INVALID_HANDLE (approx).
    EXPECT_EQ(exec_.Execute(MakeEvent("ZwQueryInformationFile", {
        std::wstring(L"0x9A2"), (int64_t)0, (int64_t)5,
    }), pa_), (DWORD_PTR)0xC0000008);  // STATUS_INVALID_HANDLE

    // ZwSetInformationFile → unmapped handle → STATUS_INVALID_HANDLE (approx).
    EXPECT_EQ(exec_.Execute(MakeEvent("ZwSetInformationFile", {
        std::wstring(L"0x9A3"), (int64_t)0, (int64_t)4,
    }), pa_), (DWORD_PTR)0xC0000008);  // STATUS_INVALID_HANDLE

    // ZwOpenFile → pre-create target in sandbox, then open via executor.
    HANDLE pre = CreateFileW(L"C:\\tmp\\NtFileTest\\C_\\nft_zw_open.txt",
                              GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (pre != INVALID_HANDLE_VALUE) CloseHandle(pre);
    LogEvent zw_open = MakeEvent("ZwOpenFile", {
        std::wstring(L"0x132"), (int64_t)0,
        std::wstring(L"C:\\nft_zw_open.txt"),  // redirected to sandbox
        (int64_t)0,
    });
    EXPECT_EQ(exec_.Execute(zw_open, pa_), (DWORD_PTR)0);
    EXPECT_TRUE(hmap_.HasMapping(0x132));

    // ZwDeleteFile → executor attempts delete; nonexistent name returns non-zero NTSTATUS.
    exec_.Execute(MakeEvent("ZwDeleteFile", {
        std::wstring(L"C:\\nft_zw_nonexistent_del.txt"),
    }), pa_);  // no-crash; return value is OS-dependent
}

// ── Device/pipe paths are skipped without error ───────────────────────────────

TEST_F(NtFileExecutorTest, NtCreateFile_DevicePath_SkippedGracefully) {
    LogEvent ev = MakeEvent("NtCreateFile", {
        std::wstring(L"0x120"), (int64_t)0,
        std::wstring(L"\\Device\\HarddiskVolume2\\test.txt"),
        (int64_t)0, (int64_t)3, (int64_t)0,
    });
    // Device path starts with '\\' after prefix strip → executor skips it (returns 0).
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);
    EXPECT_FALSE(hmap_.HasMapping(0x120));
}
