// Tests for HookExecutor after stub redesign.
//
// DESIGN (post-redesign):
//   SetWindowsHookExW/A must NOT install real Windows hooks.
//   Instead they return a non-NULL sentinel (1) so that downstream
//   handle-map lookups and UnhookWindowsHookEx calls remain defined.
//
// Why stubs?  A malware log often records dwThreadId=0 (system-wide hook).
//   Installing a system-wide hook in the replay process attaches to every
//   desktop thread for the lifetime of the process.  The no-op callback
//   approach was insufficient: the hook still adds latency to input dispatch
//   on the VM.  The stub approach avoids all hook installation.
#include <gtest/gtest.h>
#include <windows.h>
#include "replay/handle_map.h"
#include "replay/pointer_map.h"
#include "replay/executors/hook_executor.h"
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

class HookExecutorTest : public ::testing::Test {
protected:
    HandleMap    hmap_;
    PointerMap   pmap_;
    HookExecutor exec_{hmap_, pmap_};
};

// ── Core invariant: sentinel return, no real hook installed ───────────────────

TEST_F(HookExecutorTest, SetWindowsHookExW_ReturnsSentinel) {
    // dwThreadId=0: system-wide in the original log — must NOT install real hook
    auto p = MakeRaw({WH_KEYBOARD, 0, 0, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("SetWindowsHookExW"), p);
    EXPECT_NE(ret, (DWORD_PTR)0) << "Stub must return non-NULL sentinel";
}

TEST_F(HookExecutorTest, SetWindowsHookExA_ReturnsSentinel) {
    auto p = MakeRaw({WH_KEYBOARD, 0, 0, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("SetWindowsHookExA"), p);
    EXPECT_NE(ret, (DWORD_PTR)0) << "Stub must return non-NULL sentinel";
}

TEST_F(HookExecutorTest, SetWindowsHookExW_SentinelIsNotRealHook) {
    // The sentinel value (1) must not be a valid HHOOK.
    // UnhookWindowsHookEx(1) must fail — confirming no real hook was installed.
    auto p = MakeRaw({WH_KEYBOARD, 0, 0, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("SetWindowsHookExW"), p);
    EXPECT_NE(ret, (DWORD_PTR)0);
    HHOOK hh = (HHOOK)ret;
    BOOL unhooked = UnhookWindowsHookEx(hh);
    EXPECT_EQ(unhooked, FALSE) << "Sentinel must not be a real HHOOK";
}

TEST_F(HookExecutorTest, SetWindowsHookExW_SystemWideDoesNotInstall) {
    // Verify system-wide hook type (WH_MOUSE_LL requires dwThreadId=0) also stubs.
    auto p = MakeRaw({WH_MOUSE_LL, 0, 0, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("SetWindowsHookExW"), p);
    EXPECT_NE(ret, (DWORD_PTR)0);
    // Must not be a real hook: UnhookWindowsHookEx must fail
    EXPECT_EQ(UnhookWindowsHookEx((HHOOK)ret), FALSE);
}

TEST_F(HookExecutorTest, SetWindowsHookExW_ThreadLocalDoesNotInstall) {
    // Even with current thread ID in arg, stub must still return sentinel, not real hook.
    auto p = MakeRaw({WH_KEYBOARD, 0, 0, (DWORD_PTR)GetCurrentThreadId()});
    DWORD_PTR ret = exec_.Execute(MakeEvent("SetWindowsHookExW"), p);
    EXPECT_NE(ret, (DWORD_PTR)0);
    EXPECT_EQ(UnhookWindowsHookEx((HHOOK)ret), FALSE);
}

// ── Sentinel consistency across hook types ────────────────────────────────────

TEST_F(HookExecutorTest, SetWindowsHookExW_CBT_ReturnsSentinel) {
    auto p = MakeRaw({WH_CBT, 0, 0, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("SetWindowsHookExW"), p);
    EXPECT_NE(ret, (DWORD_PTR)0);
}

TEST_F(HookExecutorTest, SetWindowsHookExA_MouseLL_ReturnsSentinel) {
    auto p = MakeRaw({WH_MOUSE_LL, 0, 0, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("SetWindowsHookExA"), p);
    EXPECT_NE(ret, (DWORD_PTR)0);
}

// ── Unknown API returns 0 ─────────────────────────────────────────────────────

TEST_F(HookExecutorTest, UnknownApi_ReturnsZero) {
    PreparedArgs p;
    DWORD_PTR ret = exec_.Execute(MakeEvent("HookUnknown"), p);
    EXPECT_EQ(ret, (DWORD_PTR)0);
}
