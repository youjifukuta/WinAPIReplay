// Tests for FileExecutor: all 12 APIs in SupportedApis().
// FileExecutor reads from PreparedArgs.raw[] (Win32 style, not event.args).
// Raw arg layout mirrors the actual Win32 function signature.
#include <gtest/gtest.h>
#include <windows.h>
#include "replay/handle_map.h"
#include "replay/pointer_map.h"
#include "replay/executors/file_executor.h"
#include "replay/log_types.h"
#include "replay/arg_preparer.h"

static constexpr wchar_t kFERoot[] = L"C:\\tmp\\FETest";
static constexpr wchar_t kFile[]   = L"C:\\tmp\\FETest\\fe_test.txt";
static constexpr wchar_t kSrc[]    = L"C:\\tmp\\FETest\\fe_src.txt";
static constexpr wchar_t kDst[]    = L"C:\\tmp\\FETest\\fe_dst.txt";

static LogEvent MakeEvent(std::string api) {
    LogEvent ev;
    ev.api_name = std::move(api);
    return ev;
}

// Build PreparedArgs with up to 8 raw values; args vector mirrors raw size.
static PreparedArgs MakeRaw(std::vector<DWORD_PTR> vals) {
    PreparedArgs p;
    p.raw = std::move(vals);
    p.args.resize(p.raw.size());
    return p;
}

class FileExecutorTest : public ::testing::Test {
protected:
    HandleMap    hmap_;
    PointerMap   pmap_;
    PathSandbox  psb_{L""};  // empty = disabled (no path redirection in unit tests)
    FileExecutor exec_{hmap_, pmap_, psb_};

    static void SetUpTestSuite() {
        CreateDirectoryW(kFERoot, nullptr);
    }
    static void TearDownTestSuite() {
        DeleteFileW(kFile);
        DeleteFileW(kSrc);
        DeleteFileW(kDst);
        RemoveDirectoryW(kFERoot);
    }
};

// ── CreateFileW ───────────────────────────────────────────────────────────────

TEST_F(FileExecutorTest, CreateFileW_CreatesFile) {
    auto p = MakeRaw({
        (DWORD_PTR)kFile,
        GENERIC_WRITE, FILE_SHARE_READ, 0,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0
    });
    DWORD_PTR ret = exec_.Execute(MakeEvent("CreateFileW"), p);
    HANDLE h = (HANDLE)ret;
    EXPECT_NE(h, INVALID_HANDLE_VALUE);
    EXPECT_NE(h, (HANDLE)0);
    if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
}

// ── CreateFileA ───────────────────────────────────────────────────────────────

TEST_F(FileExecutorTest, CreateFileA_CreatesFile) {
    auto p = MakeRaw({
        (DWORD_PTR)"C:\\tmp\\FETest\\fe_test.txt",
        GENERIC_WRITE, FILE_SHARE_READ, 0,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0
    });
    DWORD_PTR ret = exec_.Execute(MakeEvent("CreateFileA"), p);
    HANDLE h = (HANDLE)ret;
    EXPECT_NE(h, INVALID_HANDLE_VALUE);
    if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
}

// ── WriteFile / ReadFile ──────────────────────────────────────────────────────

TEST_F(FileExecutorTest, WriteFile_WritesToOpenHandle) {
    HANDLE h = CreateFileW(kFile, GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    ASSERT_NE(h, INVALID_HANDLE_VALUE);

    const char data[] = "hello";
    auto p = MakeRaw({(DWORD_PTR)h, (DWORD_PTR)data, sizeof(data) - 1, 0, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("WriteFile"), p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
    CloseHandle(h);
}

TEST_F(FileExecutorTest, ReadFile_ReadsFromOpenHandle) {
    // Pre-write content
    HANDLE hw = CreateFileW(kFile, GENERIC_WRITE, 0, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    ASSERT_NE(hw, INVALID_HANDLE_VALUE);
    const char data[] = "hi";
    DWORD written;
    WriteFile(hw, data, 2, &written, nullptr);
    CloseHandle(hw);

    HANDLE hr = CreateFileW(kFile, GENERIC_READ, FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    ASSERT_NE(hr, INVALID_HANDLE_VALUE);
    char buf[16] = {};
    auto p = MakeRaw({(DWORD_PTR)hr, (DWORD_PTR)buf, 2, 0, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("ReadFile"), p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
    CloseHandle(hr);
}

// ── DeleteFileW / DeleteFileA ─────────────────────────────────────────────────

TEST_F(FileExecutorTest, DeleteFileW_DeletesExistingFile) {
    HANDLE h = CreateFileW(kFile, GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);

    auto p = MakeRaw({(DWORD_PTR)kFile});
    DWORD_PTR ret = exec_.Execute(MakeEvent("DeleteFileW"), p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
}

TEST_F(FileExecutorTest, DeleteFileA_DeletesExistingFile) {
    HANDLE h = CreateFileW(kFile, GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);

    auto p = MakeRaw({(DWORD_PTR)"C:\\tmp\\FETest\\fe_test.txt"});
    DWORD_PTR ret = exec_.Execute(MakeEvent("DeleteFileA"), p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
}

// ── CloseHandle ───────────────────────────────────────────────────────────────

TEST_F(FileExecutorTest, CloseHandle_ClosesRealHandle) {
    HANDLE h = CreateFileW(kFile, GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    ASSERT_NE(h, INVALID_HANDLE_VALUE);

    auto p = MakeRaw({(DWORD_PTR)h});
    DWORD_PTR ret = exec_.Execute(MakeEvent("CloseHandle"), p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
}

TEST_F(FileExecutorTest, CloseHandle_NullHandle_Succeeds) {
    auto p = MakeRaw({0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("CloseHandle"), p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
}

TEST_F(FileExecutorTest, CloseHandle_InvalidHandle_Succeeds) {
    auto p = MakeRaw({(DWORD_PTR)INVALID_HANDLE_VALUE});
    DWORD_PTR ret = exec_.Execute(MakeEvent("CloseHandle"), p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
}

// ── CopyFileW ─────────────────────────────────────────────────────────────────

TEST_F(FileExecutorTest, CopyFileW_CopiesFile) {
    HANDLE h = CreateFileW(kSrc, GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);

    auto p = MakeRaw({(DWORD_PTR)kSrc, (DWORD_PTR)kDst, (DWORD_PTR)FALSE});
    DWORD_PTR ret = exec_.Execute(MakeEvent("CopyFileW"), p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
}

// ── MoveFileExW ───────────────────────────────────────────────────────────────

TEST_F(FileExecutorTest, MoveFileExW_RenamesFile) {
    HANDLE h = CreateFileW(kSrc, GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    DeleteFileW(kDst);

    auto p = MakeRaw({(DWORD_PTR)kSrc, (DWORD_PTR)kDst, (DWORD_PTR)MOVEFILE_REPLACE_EXISTING});
    DWORD_PTR ret = exec_.Execute(MakeEvent("MoveFileExW"), p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
}

// ── CreateDirectoryW ──────────────────────────────────────────────────────────

TEST_F(FileExecutorTest, CreateDirectoryW_CreatesDir) {
    static const wchar_t kSubDir[] = L"C:\\tmp\\FETest\\subdir";
    auto p = MakeRaw({(DWORD_PTR)kSubDir, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("CreateDirectoryW"), p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
    RemoveDirectoryW(kSubDir);
}

TEST_F(FileExecutorTest, CreateDirectoryW_AlreadyExists_Succeeds) {
    auto p = MakeRaw({(DWORD_PTR)kFERoot, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("CreateDirectoryW"), p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);  // ERROR_ALREADY_EXISTS treated as success
}

// ── GetTempPathW ──────────────────────────────────────────────────────────────

TEST_F(FileExecutorTest, GetTempPathW_ReturnsNonZero) {
    auto p = MakeRaw({});
    DWORD_PTR ret = exec_.Execute(MakeEvent("GetTempPathW"), p);
    EXPECT_NE(ret, (DWORD_PTR)0);
}

// ── GetTempFileNameW ──────────────────────────────────────────────────────────

TEST_F(FileExecutorTest, GetTempFileNameW_CreatesUniqueFile) {
    static const wchar_t kPrefix[] = L"FET";
    auto p = MakeRaw({(DWORD_PTR)kFERoot, (DWORD_PTR)kPrefix, 0, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("GetTempFileNameW"), p);
    EXPECT_NE(ret, (DWORD_PTR)0);
}

// ── Unknown API returns 0 (no-op) ─────────────────────────────────────────────

TEST_F(FileExecutorTest, UnknownApi_ReturnsZero) {
    PreparedArgs p;
    DWORD_PTR ret = exec_.Execute(MakeEvent("NonExistentApi"), p);
    EXPECT_EQ(ret, (DWORD_PTR)0);
}
