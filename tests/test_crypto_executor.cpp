// Tests for CryptoExecutor: all 8 APIs in SupportedApis().
// CryptoExecutor reads from event.args (not p.raw) for handle values,
// and synthesizes HCRYPTPROV / HCRYPTHASH when original handles are unmapped.
#include <gtest/gtest.h>
#include <windows.h>
#include <wincrypt.h>
#include "replay/handle_map.h"
#include "replay/pointer_map.h"
#include "replay/executors/crypto_executor.h"
#include "replay/log_types.h"
#include "replay/arg_preparer.h"

static LogEvent MakeEvent(std::string api, std::vector<ArgValue> args = {}) {
    LogEvent ev;
    ev.api_name = std::move(api);
    ev.args = std::move(args);
    return ev;
}

class CryptoExecutorTest : public ::testing::Test {
protected:
    HandleMap     hmap_;
    PointerMap    pmap_;
    CryptoExecutor exec_{hmap_, pmap_};
    PreparedArgs  pa_{};

    // Typical WinMET original handle values used in tests
    static constexpr DWORD_PTR kOrigProv = 0xABC10000;
    static constexpr DWORD_PTR kOrigHash = 0xABC20000;
};

// ── CryptAcquireContextW ──────────────────────────────────────────────────────

TEST_F(CryptoExecutorTest, CryptAcquireContextW_VerifyContext_Succeeds) {
    // WinMET layout: args[0]=phProv_out, args[3]=dwProvType, args[4]=dwFlags
    // args[4]=CRYPT_VERIFYCONTEXT (0xF0000000) as hex string
    HCRYPTPROV prov = 0;
    LogEvent ev = MakeEvent("CryptAcquireContextW", {
        (int64_t)0,               // [0] phProv (pointer; argpreparer allocs buffer)
        (int64_t)0,               // [1] szContainer
        (int64_t)0,               // [2] szProvider
        (int64_t)PROV_RSA_AES,    // [3] dwProvType
        (int64_t)CRYPT_VERIFYCONTEXT, // [4] dwFlags
    });
    // PreparedArgs: raw[0] points to our prov variable
    PreparedArgs p;
    p.raw = {(DWORD_PTR)&prov, 0, 0, PROV_RSA_AES, CRYPT_VERIFYCONTEXT};
    p.args.resize(5);

    DWORD_PTR ret = exec_.Execute(ev, p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
    if (prov) CryptReleaseContext(prov, 0);
}

// ── CryptAcquireContextA ──────────────────────────────────────────────────────

TEST_F(CryptoExecutorTest, CryptAcquireContextA_VerifyContext_Succeeds) {
    HCRYPTPROV prov = 0;
    LogEvent ev = MakeEvent("CryptAcquireContextA", {
        (int64_t)0, (int64_t)0, (int64_t)0,
        (int64_t)PROV_RSA_AES, (int64_t)CRYPT_VERIFYCONTEXT,
    });
    PreparedArgs p;
    p.raw = {(DWORD_PTR)&prov, 0, 0, PROV_RSA_AES, CRYPT_VERIFYCONTEXT};
    p.args.resize(5);
    DWORD_PTR ret = exec_.Execute(ev, p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
    if (prov) CryptReleaseContext(prov, 0);
}

// ── CryptCreateHash ───────────────────────────────────────────────────────────

TEST_F(CryptoExecutorTest, CryptCreateHash_WinMETFormat_CreatesHash) {
    // WinMET records [ALG_ID, hKey=0, phHash_output] but maps ALG_ID → p.raw[0]
    // and hKey=0 → p.raw[1] (ALG_ID=0 in signature slot).
    // Executor detects: p.raw[1]==0 and p.raw[0] in ALG_ID range → swap.
    // args[2] holds original phHash value (used to register in handle_map_)
    LogEvent ev = MakeEvent("CryptCreateHash", {
        (int64_t)CALG_MD5,           // [0] ALG_ID (WinMET-captured)
        (int64_t)0,                   // [1] hKey
        std::wstring(L"0xABC20000"), // [2] original phHash value
    });
    PreparedArgs p;
    // Set raw[0]=CALG_MD5, raw[1]=0 so executor detects the WinMET format shift
    p.raw = {CALG_MD5, 0, 0, 0, 0};
    p.args.resize(5);

    DWORD_PTR ret = exec_.Execute(ev, p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
    // HandleMap should now map kOrigHash → a real HCRYPTHASH
    EXPECT_TRUE(hmap_.HasMapping(kOrigHash));
}

// ── CryptHashData ─────────────────────────────────────────────────────────────

TEST_F(CryptoExecutorTest, CryptHashData_UnmappedHandle_ReturnsFalse) {
    // With unmapped hash handle (raw[0]=0 → null HCRYPTHASH) → CryptHashData fails
    // CryptHashData does not synthesize; it requires a real pre-existing hash handle.
    LogEvent ev = MakeEvent("CryptHashData", {
        std::wstring(L"0xABC30000"),  // [0] hHash (not in hmap → resolves to null)
        (int64_t)0,                    // [1] pbData
        (int64_t)16,                   // [2] dwDataLen
        (int64_t)0,                    // [3] dwFlags
    });
    PreparedArgs p;
    p.raw = {0, 0, 16, 0};
    p.args.resize(4);
    DWORD_PTR ret = exec_.Execute(ev, p);
    EXPECT_EQ(ret, (DWORD_PTR)FALSE);  // null hHash → CryptHashData returns FALSE
}

TEST_F(CryptoExecutorTest, CryptHashData_MappedHandle_Succeeds) {
    // Acquire a real provider + hash, register in hmap_, then CryptHashData
    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    ASSERT_TRUE(CryptAcquireContextW(&prov, nullptr, nullptr,
                                      PROV_RSA_AES, CRYPT_VERIFYCONTEXT));
    ASSERT_TRUE(CryptCreateHash(prov, CALG_MD5, 0, 0, &hash));
    hmap_.Register(kOrigHash, (DWORD_PTR)hash);

    LogEvent ev = MakeEvent("CryptHashData", {
        std::wstring(L"0xABC20000"),  // [0] hHash = kOrigHash
        (int64_t)0, (int64_t)8, (int64_t)0,
    });
    PreparedArgs p;
    p.raw = {(DWORD_PTR)hash, 0, 8, 0};
    p.args.resize(4);
    DWORD_PTR ret = exec_.Execute(ev, p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);

    CryptDestroyHash(hash);
    CryptReleaseContext(prov, 0);
}

// ── CryptEncrypt / CryptDecrypt ───────────────────────────────────────────────

TEST_F(CryptoExecutorTest, CryptEncrypt_UnmappedKey_ReturnsTRUE) {
    // Unmapped hKey (raw[0]=0) → returns TRUE (fake success)
    LogEvent ev = MakeEvent("CryptEncrypt", {});
    PreparedArgs p;
    p.raw = {0, 0, FALSE, 0, 0, 0, 0};
    p.args.resize(7);
    DWORD_PTR ret = exec_.Execute(ev, p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
}

TEST_F(CryptoExecutorTest, CryptDecrypt_UnmappedKey_ReturnsTRUE) {
    LogEvent ev = MakeEvent("CryptDecrypt", {});
    PreparedArgs p;
    p.raw = {0, 0, FALSE, 0, 0, 0};
    p.args.resize(6);
    DWORD_PTR ret = exec_.Execute(ev, p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
}

// ── CryptDestroyHash ──────────────────────────────────────────────────────────

TEST_F(CryptoExecutorTest, CryptDestroyHash_MappedHash_Succeeds) {
    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    ASSERT_TRUE(CryptAcquireContextW(&prov, nullptr, nullptr,
                                      PROV_RSA_AES, CRYPT_VERIFYCONTEXT));
    ASSERT_TRUE(CryptCreateHash(prov, CALG_MD5, 0, 0, &hash));
    hmap_.Register(0xBBB1, (DWORD_PTR)hash);

    LogEvent ev = MakeEvent("CryptDestroyHash", {
        std::wstring(L"0xBBB1"),  // [0] original hHash
    });
    PreparedArgs p;
    p.raw = {(DWORD_PTR)hash};
    p.args.resize(1);
    DWORD_PTR ret = exec_.Execute(ev, p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
    // hash was destroyed; don't double-free
    CryptReleaseContext(prov, 0);
}

TEST_F(CryptoExecutorTest, CryptDestroyHash_UnmappedHash_ReturnsFalse) {
    // Unmapped hash handle (raw[0]=0 → null HCRYPTHASH) → CryptDestroyHash fails
    LogEvent ev = MakeEvent("CryptDestroyHash", {
        std::wstring(L"0xCCC1"),
    });
    PreparedArgs p;
    p.raw = {0};
    p.args.resize(1);
    DWORD_PTR ret = exec_.Execute(ev, p);
    EXPECT_EQ(ret, (DWORD_PTR)FALSE);  // null HCRYPTHASH → FALSE
}

// ── CryptReleaseContext ───────────────────────────────────────────────────────

TEST_F(CryptoExecutorTest, CryptReleaseContext_ValidProvider_Succeeds) {
    HCRYPTPROV prov = 0;
    ASSERT_TRUE(CryptAcquireContextW(&prov, nullptr, nullptr,
                                      PROV_RSA_AES, CRYPT_VERIFYCONTEXT));
    PreparedArgs p;
    p.raw = {(DWORD_PTR)prov, 0};
    p.args.resize(2);
    DWORD_PTR ret = exec_.Execute(MakeEvent("CryptReleaseContext"), p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
    // prov was released above; do not double-free
}

// ── Unknown API returns 0 ─────────────────────────────────────────────────────

TEST_F(CryptoExecutorTest, UnknownApi_ReturnsZero) {
    PreparedArgs p;
    DWORD_PTR ret = exec_.Execute(MakeEvent("CryptUnknown"), p);
    EXPECT_EQ(ret, (DWORD_PTR)0);
}
