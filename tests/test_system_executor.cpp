// Tests for SystemExecutor: all 15 APIs in SupportedApis().
// SystemExecutor ignores PreparedArgs entirely — it uses its own local buffers
// to call each API, making tests parameter-free.
#include <gtest/gtest.h>
#include <windows.h>
#include "replay/handle_map.h"
#include "replay/pointer_map.h"
#include "replay/executors/system_executor.h"
#include "replay/log_types.h"
#include "replay/arg_preparer.h"

static LogEvent MakeEvent(std::string api, std::vector<ArgValue> args = {}) {
    LogEvent ev;
    ev.api_name = std::move(api);
    ev.args = std::move(args);
    return ev;
}

class SystemExecutorTest : public ::testing::Test {
protected:
    HandleMap     hmap_;
    PointerMap    pmap_;
    SystemExecutor exec_{hmap_, pmap_};
    PreparedArgs  pa_{};
};

// ── GetLastInputInfo ──────────────────────────────────────────────────────────

TEST_F(SystemExecutorTest, GetLastInputInfo_Succeeds) {
    DWORD_PTR ret = exec_.Execute(MakeEvent("GetLastInputInfo"), pa_);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
}

// ── GetComputerNameW / A ──────────────────────────────────────────────────────

TEST_F(SystemExecutorTest, GetComputerNameW_Succeeds) {
    DWORD_PTR ret = exec_.Execute(MakeEvent("GetComputerNameW"), pa_);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
}

TEST_F(SystemExecutorTest, GetComputerNameA_Succeeds) {
    DWORD_PTR ret = exec_.Execute(MakeEvent("GetComputerNameA"), pa_);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
}

// ── GetComputerNameExW / A ────────────────────────────────────────────────────

TEST_F(SystemExecutorTest, GetComputerNameExW_Succeeds) {
    // args[0] = COMPUTER_NAME_FORMAT (ComputerNameDnsHostname = 1)
    DWORD_PTR ret = exec_.Execute(
        MakeEvent("GetComputerNameExW", {(int64_t)ComputerNameDnsHostname}), pa_);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
}

TEST_F(SystemExecutorTest, GetComputerNameExW_NetBios_Succeeds) {
    DWORD_PTR ret = exec_.Execute(
        MakeEvent("GetComputerNameExW", {(int64_t)ComputerNameNetBIOS}), pa_);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
}

TEST_F(SystemExecutorTest, GetComputerNameExA_Succeeds) {
    DWORD_PTR ret = exec_.Execute(
        MakeEvent("GetComputerNameExA", {(int64_t)ComputerNameDnsHostname}), pa_);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
}

// ── GlobalMemoryStatusEx ──────────────────────────────────────────────────────

TEST_F(SystemExecutorTest, GlobalMemoryStatusEx_Succeeds) {
    DWORD_PTR ret = exec_.Execute(MakeEvent("GlobalMemoryStatusEx"), pa_);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
}

// ── GetSystemTimeAsFileTime ───────────────────────────────────────────────────

TEST_F(SystemExecutorTest, GetSystemTimeAsFileTime_ReturnsOne) {
    DWORD_PTR ret = exec_.Execute(MakeEvent("GetSystemTimeAsFileTime"), pa_);
    EXPECT_EQ(ret, (DWORD_PTR)1);  // VOID return → always 1
}

// ── GetSystemTime ─────────────────────────────────────────────────────────────

TEST_F(SystemExecutorTest, GetSystemTime_ReturnsOne) {
    DWORD_PTR ret = exec_.Execute(MakeEvent("GetSystemTime"), pa_);
    EXPECT_EQ(ret, (DWORD_PTR)1);
}

// ── GetLocalTime ─────────────────────────────────────────────────────────────

TEST_F(SystemExecutorTest, GetLocalTime_ReturnsOne) {
    DWORD_PTR ret = exec_.Execute(MakeEvent("GetLocalTime"), pa_);
    EXPECT_EQ(ret, (DWORD_PTR)1);
}

// ── NtQuerySystemTime ─────────────────────────────────────────────────────────

TEST_F(SystemExecutorTest, NtQuerySystemTime_ReturnsStatusSuccess) {
    DWORD_PTR ret = exec_.Execute(MakeEvent("NtQuerySystemTime"), pa_);
    EXPECT_EQ(ret, (DWORD_PTR)0);  // STATUS_SUCCESS
}

// ── GetSystemInfo ─────────────────────────────────────────────────────────────

TEST_F(SystemExecutorTest, GetSystemInfo_ReturnsOne) {
    DWORD_PTR ret = exec_.Execute(MakeEvent("GetSystemInfo"), pa_);
    EXPECT_EQ(ret, (DWORD_PTR)1);
}

// ── GetNativeSystemInfo ───────────────────────────────────────────────────────

TEST_F(SystemExecutorTest, GetNativeSystemInfo_ReturnsOne) {
    DWORD_PTR ret = exec_.Execute(MakeEvent("GetNativeSystemInfo"), pa_);
    EXPECT_EQ(ret, (DWORD_PTR)1);
}

// ── GetUserNameW / A ──────────────────────────────────────────────────────────

TEST_F(SystemExecutorTest, GetUserNameW_Succeeds) {
    DWORD_PTR ret = exec_.Execute(MakeEvent("GetUserNameW"), pa_);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
}

TEST_F(SystemExecutorTest, GetUserNameA_Succeeds) {
    DWORD_PTR ret = exec_.Execute(MakeEvent("GetUserNameA"), pa_);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
}

// ── GetWriteWatch ─────────────────────────────────────────────────────────────

TEST_F(SystemExecutorTest, GetWriteWatch_ReturnsZero) {
    DWORD_PTR ret = exec_.Execute(MakeEvent("GetWriteWatch"), pa_);
    EXPECT_EQ(ret, (DWORD_PTR)0);
}

// ── Unknown API returns 0 ─────────────────────────────────────────────────────

TEST_F(SystemExecutorTest, UnknownApi_ReturnsZero) {
    DWORD_PTR ret = exec_.Execute(MakeEvent("SystemUnknown"), pa_);
    EXPECT_EQ(ret, (DWORD_PTR)0);
}
