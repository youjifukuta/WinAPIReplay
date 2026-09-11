// Tests for SyncExecutor: all 12 APIs in SupportedApis().
// SyncExecutor uses p.raw[] for args.
#include <gtest/gtest.h>
#include <windows.h>
#include "replay/handle_map.h"
#include "replay/pointer_map.h"
#include "replay/executors/sync_executor.h"
#include "replay/log_types.h"
#include "replay/arg_preparer.h"

static LogEvent MakeEvent(std::string api) {
    LogEvent ev;
    ev.api_name = std::move(api);
    return ev;
}

static PreparedArgs MakeRaw(std::vector<DWORD_PTR> vals) {
    PreparedArgs p;
    p.raw = std::move(vals);
    p.args.resize(p.raw.size());
    return p;
}

class SyncExecutorTest : public ::testing::Test {
protected:
    HandleMap    hmap_;
    PointerMap   pmap_;
    // timeout_ms_=100 to avoid blocking in Wait tests
    SyncExecutor exec_{hmap_, pmap_, 100};
};

// ── CreateMutexW ──────────────────────────────────────────────────────────────

TEST_F(SyncExecutorTest, CreateMutexW_ReturnsHandle) {
    auto p = MakeRaw({0, FALSE, (DWORD_PTR)L"Local\\SyncTestMutex"});
    DWORD_PTR ret = exec_.Execute(MakeEvent("CreateMutexW"), p);
    HANDLE h = (HANDLE)ret;
    EXPECT_NE(h, (HANDLE)nullptr);
    EXPECT_NE(h, INVALID_HANDLE_VALUE);
    if (h) CloseHandle(h);
}

// ── CreateMutexA ──────────────────────────────────────────────────────────────

TEST_F(SyncExecutorTest, CreateMutexA_ReturnsHandle) {
    auto p = MakeRaw({0, FALSE, (DWORD_PTR)"Local\\SyncTestMutexA"});
    DWORD_PTR ret = exec_.Execute(MakeEvent("CreateMutexA"), p);
    HANDLE h = (HANDLE)ret;
    EXPECT_NE(h, (HANDLE)nullptr);
    if (h) CloseHandle(h);
}

// ── OpenMutexW ────────────────────────────────────────────────────────────────

TEST_F(SyncExecutorTest, OpenMutexW_ExistingMutex_ReturnsHandle) {
    HANDLE created = CreateMutexW(nullptr, FALSE, L"Local\\SyncTestOpenMutexW");
    ASSERT_NE(created, (HANDLE)nullptr);

    auto p = MakeRaw({MUTEX_ALL_ACCESS, FALSE, (DWORD_PTR)L"Local\\SyncTestOpenMutexW"});
    DWORD_PTR ret = exec_.Execute(MakeEvent("OpenMutexW"), p);
    HANDLE h = (HANDLE)ret;
    EXPECT_NE(h, (HANDLE)nullptr);
    if (h) CloseHandle(h);
    CloseHandle(created);
}

TEST_F(SyncExecutorTest, OpenMutexW_NonExistentMutex_ReturnsNull) {
    // No mutex with this name exists → OpenMutexW returns null (no fallback)
    auto p = MakeRaw({MUTEX_ALL_ACCESS, FALSE, (DWORD_PTR)L"Local\\SyncTestNoSuchMutex"});
    DWORD_PTR ret = exec_.Execute(MakeEvent("OpenMutexW"), p);
    EXPECT_EQ(ret, (DWORD_PTR)nullptr);
}

// ── OpenMutexA ────────────────────────────────────────────────────────────────

TEST_F(SyncExecutorTest, OpenMutexA_ExistingMutex_ReturnsHandle) {
    HANDLE created = CreateMutexA(nullptr, FALSE, "Local\\SyncTestOpenMutexA");
    ASSERT_NE(created, (HANDLE)nullptr);

    auto p = MakeRaw({MUTEX_ALL_ACCESS, FALSE, (DWORD_PTR)"Local\\SyncTestOpenMutexA"});
    DWORD_PTR ret = exec_.Execute(MakeEvent("OpenMutexA"), p);
    HANDLE h = (HANDLE)ret;
    EXPECT_NE(h, (HANDLE)nullptr);
    if (h) CloseHandle(h);
    CloseHandle(created);
}

// ── ReleaseMutex ──────────────────────────────────────────────────────────────

TEST_F(SyncExecutorTest, ReleaseMutex_OwnedMutex_Succeeds) {
    HANDLE h = CreateMutexW(nullptr, TRUE, nullptr);  // create owned
    ASSERT_NE(h, (HANDLE)nullptr);

    auto p = MakeRaw({(DWORD_PTR)h});
    DWORD_PTR ret = exec_.Execute(MakeEvent("ReleaseMutex"), p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
    CloseHandle(h);
}

// ── CreateEventW ─────────────────────────────────────────────────────────────

TEST_F(SyncExecutorTest, CreateEventW_ReturnsHandle) {
    auto p = MakeRaw({0, TRUE, FALSE, (DWORD_PTR)L"Local\\SyncTestEvent"});
    DWORD_PTR ret = exec_.Execute(MakeEvent("CreateEventW"), p);
    HANDLE h = (HANDLE)ret;
    EXPECT_NE(h, (HANDLE)nullptr);
    if (h) CloseHandle(h);
}

// ── CreateEventA ─────────────────────────────────────────────────────────────

TEST_F(SyncExecutorTest, CreateEventA_ReturnsHandle) {
    auto p = MakeRaw({0, TRUE, FALSE, (DWORD_PTR)"Local\\SyncTestEventA"});
    DWORD_PTR ret = exec_.Execute(MakeEvent("CreateEventA"), p);
    HANDLE h = (HANDLE)ret;
    EXPECT_NE(h, (HANDLE)nullptr);
    if (h) CloseHandle(h);
}

// ── SetEvent ──────────────────────────────────────────────────────────────────

TEST_F(SyncExecutorTest, SetEvent_SetsEvent) {
    HANDLE h = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    ASSERT_NE(h, (HANDLE)nullptr);

    auto p = MakeRaw({(DWORD_PTR)h});
    DWORD_PTR ret = exec_.Execute(MakeEvent("SetEvent"), p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
    CloseHandle(h);
}

// ── ResetEvent ────────────────────────────────────────────────────────────────

TEST_F(SyncExecutorTest, ResetEvent_ResetsEvent) {
    HANDLE h = CreateEventW(nullptr, TRUE, TRUE, nullptr);  // initially signaled
    ASSERT_NE(h, (HANDLE)nullptr);

    auto p = MakeRaw({(DWORD_PTR)h});
    DWORD_PTR ret = exec_.Execute(MakeEvent("ResetEvent"), p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
    CloseHandle(h);
}

// ── WaitForSingleObject ───────────────────────────────────────────────────────

TEST_F(SyncExecutorTest, WaitForSingleObject_SignaledEvent_Succeeds) {
    HANDLE h = CreateEventW(nullptr, TRUE, TRUE, nullptr);  // already signaled
    ASSERT_NE(h, (HANDLE)nullptr);

    auto p = MakeRaw({(DWORD_PTR)h, INFINITE});
    DWORD_PTR ret = exec_.Execute(MakeEvent("WaitForSingleObject"), p);
    EXPECT_EQ(ret, (DWORD_PTR)WAIT_OBJECT_0);
    CloseHandle(h);
}

// ── WaitForMultipleObjects ────────────────────────────────────────────────────

TEST_F(SyncExecutorTest, WaitForMultipleObjects_NoHandles_ReturnsFailed) {
    // handle_arr is empty → executor returns WAIT_FAILED
    PreparedArgs p;
    p.raw.resize(4, 0);
    p.args.resize(4);
    p.raw[0] = 1;  // count
    // args[1].handle_arr intentionally empty → WAIT_FAILED
    DWORD_PTR ret = exec_.Execute(MakeEvent("WaitForMultipleObjects"), p);
    EXPECT_EQ(ret, (DWORD_PTR)WAIT_FAILED);
}

TEST_F(SyncExecutorTest, WaitForMultipleObjects_WithHandles_Succeeds) {
    HANDLE h = CreateEventW(nullptr, TRUE, TRUE, nullptr);  // signaled
    ASSERT_NE(h, (HANDLE)nullptr);

    PreparedArgs p;
    p.raw.resize(4, 0);
    p.args.resize(4);
    p.raw[0] = 1;           // count
    p.args[1].handle_arr = { h };
    p.raw[2] = FALSE;       // wait-all
    DWORD_PTR ret = exec_.Execute(MakeEvent("WaitForMultipleObjects"), p);
    EXPECT_EQ(ret, (DWORD_PTR)WAIT_OBJECT_0);
    CloseHandle(h);
}

// ── WaitForMultipleObjectsEx ──────────────────────────────────────────────────

TEST_F(SyncExecutorTest, WaitForMultipleObjectsEx_WithHandles_Succeeds) {
    HANDLE h = CreateEventW(nullptr, TRUE, TRUE, nullptr);
    ASSERT_NE(h, (HANDLE)nullptr);

    PreparedArgs p;
    p.raw.resize(5, 0);
    p.args.resize(5);
    p.raw[0] = 1;
    p.args[1].handle_arr = { h };
    p.raw[2] = FALSE;
    p.raw[4] = FALSE;  // alertable
    DWORD_PTR ret = exec_.Execute(MakeEvent("WaitForMultipleObjectsEx"), p);
    EXPECT_EQ(ret, (DWORD_PTR)WAIT_OBJECT_0);
    CloseHandle(h);
}

// ── Unknown API returns 0 ─────────────────────────────────────────────────────

TEST_F(SyncExecutorTest, UnknownApi_ReturnsZero) {
    PreparedArgs p;
    DWORD_PTR ret = exec_.Execute(MakeEvent("SyncUnknown"), p);
    EXPECT_EQ(ret, (DWORD_PTR)0);
}
