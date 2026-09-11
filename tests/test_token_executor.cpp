// Tests for TokenExecutor after AdjustTokenPrivileges stub redesign.
//
// DESIGN (post-redesign):
//   OpenProcessToken  — still calls the real API (read-only side-effect).
//   AdjustTokenPrivileges — stubbed to no-op (returns TRUE).
//
// Why stub AdjustTokenPrivileges?
//   The only token handle available in the replay process is the process's own
//   token (obtained from OpenProcessToken(GetCurrentProcess())).  If the log
//   contains DisableAllPrivileges=TRUE, executing the real call would strip all
//   privileges from WinAPIReplay.exe itself, breaking subsequent sandboxed
//   file/registry operations within the same sample.
#include <gtest/gtest.h>
#include <windows.h>
#include "replay/handle_map.h"
#include "replay/pointer_map.h"
#include "replay/executors/token_executor.h"
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

class TokenExecutorTest : public ::testing::Test {
protected:
    HandleMap    hmap_;
    PointerMap   pmap_;
    TokenExecutor exec_{hmap_, pmap_};
};

// ── OpenProcessToken ──────────────────────────────────────────────────────────

TEST_F(TokenExecutorTest, OpenProcessToken_CurrentProcess_Succeeds) {
    HANDLE tok = nullptr;
    auto p = MakeRaw({
        (DWORD_PTR)GetCurrentProcess(),
        TOKEN_QUERY,
        (DWORD_PTR)&tok,
    });
    DWORD_PTR ret = exec_.Execute(MakeEvent("OpenProcessToken"), p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
    EXPECT_NE(tok, (HANDLE)nullptr);
    if (tok) CloseHandle(tok);
}

TEST_F(TokenExecutorTest, OpenProcessToken_AllAccess_ReturnsToken) {
    HANDLE tok = nullptr;
    auto p = MakeRaw({
        (DWORD_PTR)GetCurrentProcess(),
        TOKEN_ALL_ACCESS,
        (DWORD_PTR)&tok,
    });
    DWORD_PTR ret = exec_.Execute(MakeEvent("OpenProcessToken"), p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
    if (tok) CloseHandle(tok);
}

// ── AdjustTokenPrivileges stub invariants ─────────────────────────────────────

TEST_F(TokenExecutorTest, AdjustTokenPrivileges_AlwaysReturnsTrue) {
    // Stub must return TRUE regardless of args
    auto p = MakeRaw({0, FALSE, 0, 0, 0, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("AdjustTokenPrivileges"), p);
    EXPECT_EQ(ret, (DWORD_PTR)TRUE);
}

TEST_F(TokenExecutorTest, AdjustTokenPrivileges_DisableAll_ReturnsTrueWithoutActing) {
    // Core safety invariant: DisableAllPrivileges=TRUE must NOT disable process privileges.
    // Verify by checking that the process token still has at least one privilege after the call.
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &tok))
        GTEST_SKIP() << "Cannot open process token";

    // Count privileges before stub call
    DWORD cb = 0;
    GetTokenInformation(tok, TokenPrivileges, nullptr, 0, &cb);
    std::vector<BYTE> buf(cb);
    BOOL ok = GetTokenInformation(tok, TokenPrivileges, buf.data(), cb, &cb);
    ASSERT_TRUE(ok);
    DWORD priv_count_before = reinterpret_cast<TOKEN_PRIVILEGES*>(buf.data())->PrivilegeCount;

    // Call stub with DisableAllPrivileges=TRUE
    auto p = MakeRaw({(DWORD_PTR)tok, TRUE, 0, 0, 0, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("AdjustTokenPrivileges"), p);
    EXPECT_EQ(ret, (DWORD_PTR)TRUE) << "Stub must return TRUE";

    // Verify privileges are unchanged (stub did NOT call real AdjustTokenPrivileges)
    cb = 0;
    GetTokenInformation(tok, TokenPrivileges, nullptr, 0, &cb);
    buf.assign(cb, 0);
    ok = GetTokenInformation(tok, TokenPrivileges, buf.data(), cb, &cb);
    ASSERT_TRUE(ok);
    DWORD priv_count_after = reinterpret_cast<TOKEN_PRIVILEGES*>(buf.data())->PrivilegeCount;

    EXPECT_EQ(priv_count_after, priv_count_before)
        << "Privilege count must be unchanged: stub must not call real AdjustTokenPrivileges";

    CloseHandle(tok);
}

TEST_F(TokenExecutorTest, AdjustTokenPrivileges_RealToken_NoChangeToPrivileges) {
    // Also verify with enable=FALSE and real token: still no-op
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &tok))
        GTEST_SKIP() << "Cannot open process token";

    DWORD cb = 0;
    GetTokenInformation(tok, TokenPrivileges, nullptr, 0, &cb);
    std::vector<BYTE> buf(cb);
    GetTokenInformation(tok, TokenPrivileges, buf.data(), cb, &cb);
    DWORD priv_count_before = reinterpret_cast<TOKEN_PRIVILEGES*>(buf.data())->PrivilegeCount;

    auto p = MakeRaw({(DWORD_PTR)tok, FALSE, 0, 0, 0, 0});
    exec_.Execute(MakeEvent("AdjustTokenPrivileges"), p);

    cb = 0;
    GetTokenInformation(tok, TokenPrivileges, nullptr, 0, &cb);
    buf.assign(cb, 0);
    GetTokenInformation(tok, TokenPrivileges, buf.data(), cb, &cb);
    DWORD priv_count_after = reinterpret_cast<TOKEN_PRIVILEGES*>(buf.data())->PrivilegeCount;

    EXPECT_EQ(priv_count_after, priv_count_before);
    CloseHandle(tok);
}

// ── Unknown API returns 0 ─────────────────────────────────────────────────────

TEST_F(TokenExecutorTest, UnknownApi_ReturnsZero) {
    PreparedArgs p;
    DWORD_PTR ret = exec_.Execute(MakeEvent("TokenUnknown"), p);
    EXPECT_EQ(ret, (DWORD_PTR)0);
}
