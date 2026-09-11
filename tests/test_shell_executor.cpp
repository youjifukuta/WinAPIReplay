// Tests for ShellExecutor: all 3 APIs in SupportedApis().
// With no_spawn_=true all three return 33 (success code > 32) immediately
// without actually executing anything.
#include <gtest/gtest.h>
#include <windows.h>
#include "replay/handle_map.h"
#include "replay/pointer_map.h"
#include "replay/executors/shell_executor.h"
#include "replay/log_types.h"
#include "replay/arg_preparer.h"

static LogEvent MakeEvent(std::string api, std::vector<ArgValue> args = {}) {
    LogEvent ev;
    ev.api_name = std::move(api);
    ev.args = std::move(args);
    return ev;
}

static PreparedArgs MakeRaw(std::vector<DWORD_PTR> vals) {
    PreparedArgs p;
    p.raw = std::move(vals);
    p.args.resize(p.raw.size());
    return p;
}

class ShellExecutorTest : public ::testing::Test {
protected:
    HandleMap     hmap_;
    PointerMap    pmap_;
    // no_spawn_=true: all shell execute paths return 33 without spawning
    ShellExecutor exec_{hmap_, pmap_, true};
    PreparedArgs  pa_{};
};

// ── ShellExecuteW (no_spawn) ──────────────────────────────────────────────────

TEST_F(ShellExecutorTest, ShellExecuteW_NoSpawn_Returns33) {
    auto p = MakeRaw({0, (DWORD_PTR)L"open", (DWORD_PTR)L"calc.exe", 0, 0, SW_HIDE});
    DWORD_PTR ret = exec_.Execute(MakeEvent("ShellExecuteW"), p);
    EXPECT_GT(ret, (DWORD_PTR)32);  // >32 means success for ShellExecuteW
}

// ── ShellExecuteA (no_spawn) ──────────────────────────────────────────────────

TEST_F(ShellExecutorTest, ShellExecuteA_NoSpawn_Returns33) {
    auto p = MakeRaw({0, (DWORD_PTR)"open", (DWORD_PTR)"calc.exe", 0, 0, SW_HIDE});
    DWORD_PTR ret = exec_.Execute(MakeEvent("ShellExecuteA"), p);
    EXPECT_GT(ret, (DWORD_PTR)32);
}

// ── WinExec (no_spawn) ────────────────────────────────────────────────────────

TEST_F(ShellExecutorTest, WinExec_NoSpawn_Returns33) {
    // WinExec takes LPCSTR; executor receives wchar_t* from ArgPreparer,
    // then converts with CP_ACP.  With no_spawn_ it never reaches the convert step.
    auto p = MakeRaw({(DWORD_PTR)L"calc.exe", SW_HIDE});
    DWORD_PTR ret = exec_.Execute(MakeEvent("WinExec"), p);
    EXPECT_GT(ret, (DWORD_PTR)31);  // >31 means success for WinExec
}

TEST_F(ShellExecutorTest, WinExec_NullCommand_Returns33BecauseNoSpawn) {
    auto p = MakeRaw({0, SW_HIDE});
    DWORD_PTR ret = exec_.Execute(MakeEvent("WinExec"), p);
    // no_spawn_ short-circuits before null check → 33
    EXPECT_EQ(ret, (DWORD_PTR)33);
}

// ── Unknown API returns 0 ─────────────────────────────────────────────────────

TEST_F(ShellExecutorTest, UnknownApi_NoSpawnReturnsSameAs33) {
    // no_spawn_ applies even to unknown names because the check is first
    DWORD_PTR ret = exec_.Execute(MakeEvent("ShellUnknown"), pa_);
    EXPECT_EQ(ret, (DWORD_PTR)33);
}

// ── ShellExecutor with spawn allowed ──────────────────────────────────────────

TEST(ShellExecutorNoSpawnFalse, WinExec_NullPath_ReturnsError) {
    HandleMap h; PointerMap p;
    ShellExecutor exec{h, p, false};

    PreparedArgs pa;
    pa.raw = {0, SW_HIDE};
    pa.args.resize(2);
    // Null wchar_t* → executor returns ERROR_FILE_NOT_FOUND (2) = HINSTANCE_ERROR
    DWORD_PTR ret = exec.Execute(MakeEvent("WinExec"), pa);
    EXPECT_LE(ret, (DWORD_PTR)32);  // ≤32 means failure for WinExec
}
