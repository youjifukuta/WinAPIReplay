// Tests for RegistryExecutor: all 11 APIs in SupportedApis().
// RegistryExecutor uses p.raw[] for args and has a RegistrySandbox dependency.
// The Win32 registry sandbox root is HKCU\Software\WinAPIReplaySandbox.
#include <gtest/gtest.h>
#include <windows.h>
#include "replay/handle_map.h"
#include "replay/pointer_map.h"
#include "replay/registry_sandbox.h"
#include "replay/executors/registry_executor.h"
#include "replay/log_types.h"
#include "replay/arg_preparer.h"

static const wchar_t* kSandboxRoot = L"Software\\WinAPIReplaySandbox";

// Sandbox subkey used for Win32 HKCU create/open tests.
// RegistrySandbox redirects HKCU\Software\RETest → HKCU\Software\WinAPIReplaySandbox\HKCU\Software\RETest
static const wchar_t* kTestSub  = L"Software\\RETest";
static const wchar_t* kSbSub    = L"Software\\WinAPIReplaySandbox\\HKCU\\Software\\RETest";

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

class RegistryExecutorTest : public ::testing::Test {
protected:
    HandleMap        hmap_;
    PointerMap       pmap_;
    RegistrySandbox  sb_;
    RegistryExecutor exec_{hmap_, pmap_, sb_};

    static void SetUpTestSuite() {
        // Pre-create the sandbox path that RegOpenKeyExW expects to already exist
        HKEY hk = nullptr;
        RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\WinAPIReplaySandbox\\HKCU\\Software\\RETest",
                        0, nullptr, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &hk, nullptr);
        if (hk) RegCloseKey(hk);
    }
    static void TearDownTestSuite() {
        RegDeleteTreeW(HKEY_CURRENT_USER, kSandboxRoot);
    }

    void SetUp() override {
        sb_.Enable();
        exec_.Initialize();
    }
    void TearDown() override {}
};

// ── RegCreateKeyExW ───────────────────────────────────────────────────────────

TEST_F(RegistryExecutorTest, RegCreateKeyExW_CreatesKeyAndRegistersHandle) {
    // args[0]=root hex, args[1]=subkey, args[3]=samDesired hex, args[4]=out-hkey hex
    LogEvent ev = MakeEvent("RegCreateKeyExW", {
        (int64_t)(DWORD_PTR)HKEY_CURRENT_USER,  // [0] root
        std::wstring(kTestSub),                  // [1] subkey
        (int64_t)0,                              // [2]
        std::wstring(L"0x20019"),                // [3] samDesired (KEY_READ|KEY_WRITE hex)
        std::wstring(L"0x300"),                  // [4] orig output hkey
    });
    PreparedArgs p = MakeRaw({(DWORD_PTR)HKEY_CURRENT_USER, (DWORD_PTR)kTestSub, 0, 0, 0});
    DWORD_PTR ret = exec_.Execute(ev, p);
    EXPECT_EQ(ret, (DWORD_PTR)ERROR_SUCCESS);
    EXPECT_TRUE(hmap_.HasMapping(0x300));
}

// ── RegCreateKeyExA ───────────────────────────────────────────────────────────

TEST_F(RegistryExecutorTest, RegCreateKeyExA_CreatesKey) {
    LogEvent ev = MakeEvent("RegCreateKeyExA", {
        (int64_t)(DWORD_PTR)HKEY_CURRENT_USER,
        std::wstring(L"Software\\RETest"),
        (int64_t)0,
        std::wstring(L"0x20019"),
        std::wstring(L"0x301"),
    });
    PreparedArgs p = MakeRaw({(DWORD_PTR)HKEY_CURRENT_USER,
                               (DWORD_PTR)"Software\\RETest", 0, 0, 0});
    DWORD_PTR ret = exec_.Execute(ev, p);
    EXPECT_EQ(ret, (DWORD_PTR)ERROR_SUCCESS);
    EXPECT_TRUE(hmap_.HasMapping(0x301));
}

// ── RegOpenKeyExW ─────────────────────────────────────────────────────────────

TEST_F(RegistryExecutorTest, RegOpenKeyExW_OpensExistingSandboxKey) {
    // The sandbox key was pre-created in SetUpTestSuite.
    // ArgPreparer redirects HKCU+kTestSub → sandbox; for direct test we pass
    // the sandbox root (HKCU) and the sandbox-redirected path as raw args.
    std::wstring sbPath = L"Software\\WinAPIReplaySandbox\\HKCU\\Software\\RETest";
    HKEY hkOut = nullptr;
    PreparedArgs p = MakeRaw({
        (DWORD_PTR)HKEY_CURRENT_USER,
        (DWORD_PTR)sbPath.c_str(),
        0, KEY_READ,
        (DWORD_PTR)&hkOut
    });
    DWORD_PTR ret = exec_.Execute(MakeEvent("RegOpenKeyExW"), p);
    EXPECT_EQ(ret, (DWORD_PTR)ERROR_SUCCESS);
    if (hkOut) RegCloseKey(hkOut);
}

// ── RegOpenKeyExA ─────────────────────────────────────────────────────────────

TEST_F(RegistryExecutorTest, RegOpenKeyExA_OpensExistingSandboxKey) {
    HKEY hkOut = nullptr;
    PreparedArgs p = MakeRaw({
        (DWORD_PTR)HKEY_CURRENT_USER,
        (DWORD_PTR)"Software\\WinAPIReplaySandbox\\HKCU\\Software\\RETest",
        0, KEY_READ,
        (DWORD_PTR)&hkOut
    });
    DWORD_PTR ret = exec_.Execute(MakeEvent("RegOpenKeyExA"), p);
    EXPECT_EQ(ret, (DWORD_PTR)ERROR_SUCCESS);
    if (hkOut) RegCloseKey(hkOut);
}

// ── RegSetValueExW ────────────────────────────────────────────────────────────

TEST_F(RegistryExecutorTest, RegSetValueExW_SetsStringValue) {
    // Get a real sandbox key handle
    HKEY hk = nullptr;
    RegCreateKeyExW(HKEY_CURRENT_USER, kSbSub, 0, nullptr,
                    REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &hk, nullptr);
    ASSERT_NE(hk, (HKEY)nullptr);
    // Register it in HandleMap
    hmap_.Register(0x400, (DWORD_PTR)hk);

    LogEvent ev = MakeEvent("RegSetValueExW", {
        std::wstring(L"0x400"),     // [0] handle
        std::wstring(L"TestVal"),   // [1] value name
        (int64_t)REG_SZ,            // [2] dwType
        std::wstring(L"hello"),     // [3] data
        (int64_t)12,                // [4] cbData
    });
    PreparedArgs p = MakeRaw({(DWORD_PTR)hk, (DWORD_PTR)L"TestVal", 0, 0, 0});
    DWORD_PTR ret = exec_.Execute(ev, p);
    EXPECT_EQ(ret, (DWORD_PTR)ERROR_SUCCESS);
    RegCloseKey(hk);
}

// ── RegSetValueExA ────────────────────────────────────────────────────────────

TEST_F(RegistryExecutorTest, RegSetValueExA_SetsValue) {
    HKEY hk = nullptr;
    RegCreateKeyExW(HKEY_CURRENT_USER, kSbSub, 0, nullptr,
                    REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &hk, nullptr);
    ASSERT_NE(hk, (HKEY)nullptr);
    hmap_.Register(0x401, (DWORD_PTR)hk);

    LogEvent ev = MakeEvent("RegSetValueExA", {
        std::wstring(L"0x401"),
        std::wstring(L"TestValA"),
        (int64_t)REG_SZ,
        std::wstring(L"world"),
        (int64_t)6,
    });
    PreparedArgs p = MakeRaw({(DWORD_PTR)hk, (DWORD_PTR)"TestValA", 0, 0, 0});
    DWORD_PTR ret = exec_.Execute(ev, p);
    EXPECT_EQ(ret, (DWORD_PTR)ERROR_SUCCESS);
    RegCloseKey(hk);
}

// ── RegQueryValueExW ──────────────────────────────────────────────────────────

TEST_F(RegistryExecutorTest, RegQueryValueExW_WithZeroHandle_Succeeds) {
    // Unmapped handle (0) → executor returns ERROR_SUCCESS
    PreparedArgs p = MakeRaw({0, (DWORD_PTR)L"Test", 0, 0, 0, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("RegQueryValueExW"), p);
    EXPECT_EQ(ret, (DWORD_PTR)ERROR_SUCCESS);
}

TEST_F(RegistryExecutorTest, RegQueryValueExW_WithMappedHandle_QueriesValue) {
    // Pre-set a value, then query it
    HKEY hk = nullptr;
    RegCreateKeyExW(HKEY_CURRENT_USER, kSbSub, 0, nullptr,
                    REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &hk, nullptr);
    ASSERT_NE(hk, (HKEY)nullptr);
    DWORD val = 42;
    RegSetValueExW(hk, L"QVal", 0, REG_DWORD, (const BYTE*)&val, sizeof(val));

    DWORD type = 0, sz = sizeof(val), out = 0;
    PreparedArgs p = MakeRaw({(DWORD_PTR)hk, (DWORD_PTR)L"QVal",
                               0, (DWORD_PTR)&type, (DWORD_PTR)&out, (DWORD_PTR)&sz});
    DWORD_PTR ret = exec_.Execute(MakeEvent("RegQueryValueExW"), p);
    EXPECT_EQ(ret, (DWORD_PTR)ERROR_SUCCESS);
    RegCloseKey(hk);
}

// ── RegQueryValueExA ──────────────────────────────────────────────────────────

TEST_F(RegistryExecutorTest, RegQueryValueExA_WithZeroHandle_Succeeds) {
    PreparedArgs p = MakeRaw({0, (DWORD_PTR)"Test", 0, 0, 0, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("RegQueryValueExA"), p);
    EXPECT_EQ(ret, (DWORD_PTR)ERROR_SUCCESS);
}

// ── RegDeleteValueW ───────────────────────────────────────────────────────────

TEST_F(RegistryExecutorTest, RegDeleteValueW_WithZeroHandle_Succeeds) {
    PreparedArgs p = MakeRaw({0, (DWORD_PTR)L"val"});
    DWORD_PTR ret = exec_.Execute(MakeEvent("RegDeleteValueW"), p);
    EXPECT_EQ(ret, (DWORD_PTR)ERROR_SUCCESS);
}

TEST_F(RegistryExecutorTest, RegDeleteValueW_DeletesExistingValue) {
    HKEY hk = nullptr;
    RegCreateKeyExW(HKEY_CURRENT_USER, kSbSub, 0, nullptr,
                    REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &hk, nullptr);
    ASSERT_NE(hk, (HKEY)nullptr);
    DWORD v = 1;
    RegSetValueExW(hk, L"DelVal", 0, REG_DWORD, (const BYTE*)&v, sizeof(v));

    PreparedArgs p = MakeRaw({(DWORD_PTR)hk, (DWORD_PTR)L"DelVal"});
    DWORD_PTR ret = exec_.Execute(MakeEvent("RegDeleteValueW"), p);
    EXPECT_EQ(ret, (DWORD_PTR)ERROR_SUCCESS);
    RegCloseKey(hk);
}

// ── RegCloseKey ───────────────────────────────────────────────────────────────

TEST_F(RegistryExecutorTest, RegCloseKey_ClosesRealHandle) {
    HKEY hk = nullptr;
    RegCreateKeyExW(HKEY_CURRENT_USER, kSbSub, 0, nullptr,
                    REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &hk, nullptr);
    ASSERT_NE(hk, (HKEY)nullptr);

    PreparedArgs p = MakeRaw({(DWORD_PTR)hk});
    DWORD_PTR ret = exec_.Execute(MakeEvent("RegCloseKey"), p);
    EXPECT_EQ(ret, (DWORD_PTR)ERROR_SUCCESS);
}

TEST_F(RegistryExecutorTest, RegCloseKey_NullHandle_Succeeds) {
    PreparedArgs p = MakeRaw({0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("RegCloseKey"), p);
    EXPECT_EQ(ret, (DWORD_PTR)ERROR_SUCCESS);
}

// ── RegDeleteKeyW ─────────────────────────────────────────────────────────────

TEST_F(RegistryExecutorTest, RegDeleteKeyW_WithZeroHandle_Succeeds) {
    PreparedArgs p = MakeRaw({0, (DWORD_PTR)L"sub"});
    DWORD_PTR ret = exec_.Execute(MakeEvent("RegDeleteKeyW"), p);
    EXPECT_EQ(ret, (DWORD_PTR)ERROR_SUCCESS);
}

// ── Unknown API returns 0 ─────────────────────────────────────────────────────

TEST_F(RegistryExecutorTest, UnknownApi_ReturnsZero) {
    PreparedArgs p;
    DWORD_PTR ret = exec_.Execute(MakeEvent("RegUnknown"), p);
    EXPECT_EQ(ret, (DWORD_PTR)0);
}
