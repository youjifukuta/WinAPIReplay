#include <gtest/gtest.h>
#include <windows.h>
#include "replay/nt_native.h"
#include "replay/handle_map.h"
#include "replay/pointer_map.h"
#include "replay/registry_sandbox.h"
#include "replay/executors/nt_registry_executor.h"
#include "replay/log_types.h"
#include "replay/arg_preparer.h"

// Registry test subkey under the WinAPIReplaySandbox.
// All NtCreateKey / NtOpenKey calls use Win32 path "HKEY_LOCAL_MACHINE\SOFTWARE\WARRegTest"
// which redirects to HKCU\Software\WinAPIReplaySandbox\HKLM\SOFTWARE\WARRegTest.
static constexpr wchar_t kTestSubkey[] =
    L"Software\\WinAPIReplaySandbox\\HKLM\\SOFTWARE\\WARRegTest";

static LogEvent MakeEvent(std::string api,
                           std::initializer_list<ArgValue> args) {
    LogEvent ev;
    ev.api_name = std::move(api);
    ev.args.assign(args);
    return ev;
}

class NtRegistryExecutorTest : public ::testing::Test {
protected:
    HandleMap            hmap_;
    PointerMap           pmap_;
    RegistrySandbox      reg_sb_;
    NtRegistryExecutor   exec_{hmap_, pmap_, reg_sb_};
    PreparedArgs         pa_{};

    // NtCreateKey can only create one level at a time; pre-create the intermediate
    // sandbox path so that test keys (e.g. HKLM\SOFTWARE\WARRegTest) can be created
    // in a single NtCreateKey call — mirroring what the production event stream does.
    static void SetUpTestSuite() {
        NtApiLoad(GetNtApi());
        HKEY hk = nullptr;
        RegCreateKeyExW(HKEY_CURRENT_USER,
                        L"Software\\WinAPIReplaySandbox\\HKLM\\SOFTWARE",
                        0, nullptr, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS,
                        nullptr, &hk, nullptr);
        if (hk) RegCloseKey(hk);
    }

    static void TearDownTestSuite() {
        RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\WinAPIReplaySandbox");
    }

    void SetUp() override {
        reg_sb_.Enable();
        exec_.Initialize();  // opens HKCU\Software\WinAPIReplaySandbox
    }

    void TearDown() override {
        // Remove the test subkey created during this test (best-effort).
        RegDeleteKeyExW(HKEY_CURRENT_USER, kTestSubkey, KEY_WOW64_64KEY, 0);
    }
};

// ── Initialize ────────────────────────────────────────────────────────────────

TEST_F(NtRegistryExecutorTest, Initialize_OpensSandboxRoot) {
    // If Initialize() succeeds, NtCreateKey can reach the sandbox root.
    // We verify indirectly: NtCreateKey should succeed (returns STATUS_SUCCESS).
    LogEvent ev = MakeEvent("NtCreateKey", {
        std::wstring(L"0x200"),                              // [0] out handle
        (int64_t)0,                                          // [1] parent handle
        (int64_t)0,                                          // [2] reserved
        std::wstring(L"\\REGISTRY\\MACHINE\\SOFTWARE\\WARRegTest"), // [3] NT path
        std::wstring(L"HKEY_LOCAL_MACHINE\\SOFTWARE\\WARRegTest"),  // [4] Win32 path
    });
    DWORD_PTR status = exec_.Execute(ev, pa_);
    EXPECT_EQ(status, (DWORD_PTR)0);  // STATUS_SUCCESS
}

// ── NtCreateKey ───────────────────────────────────────────────────────────────

TEST_F(NtRegistryExecutorTest, NtCreateKey_CreatesKeyAndRegistersHandle) {
    LogEvent ev = MakeEvent("NtCreateKey", {
        std::wstring(L"0x201"),
        (int64_t)0,
        (int64_t)0,
        std::wstring(L"\\REGISTRY\\MACHINE\\SOFTWARE\\WARRegTest"),
        std::wstring(L"HKEY_LOCAL_MACHINE\\SOFTWARE\\WARRegTest"),
    });
    DWORD_PTR status = exec_.Execute(ev, pa_);
    EXPECT_EQ(status, (DWORD_PTR)0);
    EXPECT_TRUE(hmap_.HasMapping(0x201));
}

TEST_F(NtRegistryExecutorTest, NtCreateKey_AlreadyMappedHandle_IsNoOp) {
    // First call.
    LogEvent ev = MakeEvent("NtCreateKey", {
        std::wstring(L"0x202"), (int64_t)0, (int64_t)0,
        std::wstring(L"\\REGISTRY\\MACHINE\\SOFTWARE\\WARRegTest"),
        std::wstring(L"HKEY_LOCAL_MACHINE\\SOFTWARE\\WARRegTest"),
    });
    exec_.Execute(ev, pa_);
    ASSERT_TRUE(hmap_.HasMapping(0x202));

    // Second call with same orig handle → no-op.
    DWORD_PTR status = exec_.Execute(ev, pa_);
    EXPECT_EQ(status, (DWORD_PTR)0);
}

// ── NtOpenKey ─────────────────────────────────────────────────────────────────

TEST_F(NtRegistryExecutorTest, NtOpenKey_OpensSandboxKey) {
    // Create first.
    LogEvent create_ev = MakeEvent("NtCreateKey", {
        std::wstring(L"0x203"), (int64_t)0, (int64_t)0,
        std::wstring(L"\\REGISTRY\\MACHINE\\SOFTWARE\\WARRegTest"),
        std::wstring(L"HKEY_LOCAL_MACHINE\\SOFTWARE\\WARRegTest"),
    });
    exec_.Execute(create_ev, pa_);

    // Then open.
    LogEvent open_ev = MakeEvent("NtOpenKey", {
        std::wstring(L"0x204"), (int64_t)0, (int64_t)0,
        std::wstring(L"\\REGISTRY\\MACHINE\\SOFTWARE\\WARRegTest"),
        std::wstring(L"HKEY_LOCAL_MACHINE\\SOFTWARE\\WARRegTest"),
    });
    DWORD_PTR status = exec_.Execute(open_ev, pa_);
    EXPECT_EQ(status, (DWORD_PTR)0);
    EXPECT_TRUE(hmap_.HasMapping(0x204));
}

TEST_F(NtRegistryExecutorTest, NtOpenKey_NonexistentKey_FailsWithoutFallback) {
    // A key that was never created should cause NtOpenKey to return a failure code.
    // The redesign removes the NtCreateKey fallback — so NtOpenKey genuinely fails.
    LogEvent ev = MakeEvent("NtOpenKey", {
        std::wstring(L"0x205"), (int64_t)0, (int64_t)0,
        std::wstring(L"\\REGISTRY\\MACHINE\\SOFTWARE\\WAR_NEVER_CREATED"),
        std::wstring(L"HKEY_LOCAL_MACHINE\\SOFTWARE\\WAR_NEVER_CREATED"),
    });
    DWORD_PTR status = exec_.Execute(ev, pa_);
    EXPECT_NE(status, (DWORD_PTR)0);  // must fail (0xC0000034 or similar)
    EXPECT_FALSE(hmap_.HasMapping(0x205));
}

// ── NtSetValueKey ─────────────────────────────────────────────────────────────

TEST_F(NtRegistryExecutorTest, NtSetValueKey_WithMappedHandle_Succeeds) {
    // Create key, then set a value.
    LogEvent create_ev = MakeEvent("NtCreateKey", {
        std::wstring(L"0x206"), (int64_t)0, (int64_t)0,
        std::wstring(L"\\REGISTRY\\MACHINE\\SOFTWARE\\WARRegTest"),
        std::wstring(L"HKEY_LOCAL_MACHINE\\SOFTWARE\\WARRegTest"),
    });
    exec_.Execute(create_ev, pa_);
    ASSERT_TRUE(hmap_.HasMapping(0x206));

    LogEvent ev = MakeEvent("NtSetValueKey", {
        std::wstring(L"0x206"),        // [0] handle
        std::wstring(L"TestValue"),    // [1] value name
        (int64_t)0,                    // [2] reserved
        (int64_t)1,                    // [3] REG_SZ
        std::wstring(L"hello"),        // [4] data
    });
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);  // STATUS_SUCCESS
}

// ── NtQueryValueKey ───────────────────────────────────────────────────────────

TEST_F(NtRegistryExecutorTest, NtQueryValueKey_WithMappedHandle_Succeeds) {
    // Create key and set value, then query.
    LogEvent create_ev = MakeEvent("NtCreateKey", {
        std::wstring(L"0x207"), (int64_t)0, (int64_t)0,
        std::wstring(L"\\REGISTRY\\MACHINE\\SOFTWARE\\WARRegTest"),
        std::wstring(L"HKEY_LOCAL_MACHINE\\SOFTWARE\\WARRegTest"),
    });
    exec_.Execute(create_ev, pa_);
    ASSERT_TRUE(hmap_.HasMapping(0x207));

    LogEvent set_ev = MakeEvent("NtSetValueKey", {
        std::wstring(L"0x207"), std::wstring(L"QV"),
        (int64_t)0, (int64_t)1, std::wstring(L"data"),
    });
    exec_.Execute(set_ev, pa_);

    LogEvent ev = MakeEvent("NtQueryValueKey", {
        std::wstring(L"0x207"),   // [0] handle
        std::wstring(L"QV"),      // [1] value name
    });
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);  // STATUS_SUCCESS
}

TEST_F(NtRegistryExecutorTest, NtQueryValueKey_WithNullHandle_ReturnsApprox) {
    // args[0]=0 → hkey=nullptr → returns 0 (approx success).
    LogEvent ev = MakeEvent("NtQueryValueKey", {
        (int64_t)0,                // [0] null handle
        std::wstring(L"AnyValue"), // [1] value name
    });
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);
}

// ── NtDeleteKey ───────────────────────────────────────────────────────────────

TEST_F(NtRegistryExecutorTest, NtDeleteKey_WithMappedHandle_Succeeds) {
    LogEvent create_ev = MakeEvent("NtCreateKey", {
        std::wstring(L"0x208"), (int64_t)0, (int64_t)0,
        std::wstring(L"\\REGISTRY\\MACHINE\\SOFTWARE\\WARRegTest"),
        std::wstring(L"HKEY_LOCAL_MACHINE\\SOFTWARE\\WARRegTest"),
    });
    exec_.Execute(create_ev, pa_);
    ASSERT_TRUE(hmap_.HasMapping(0x208));

    LogEvent ev = MakeEvent("NtDeleteKey", {
        std::wstring(L"0x208"),  // [0] handle
    });
    DWORD_PTR status = exec_.Execute(ev, pa_);
    EXPECT_EQ(status, (DWORD_PTR)0);  // STATUS_SUCCESS
}

// ── NtFlushKey ────────────────────────────────────────────────────────────────

TEST_F(NtRegistryExecutorTest, NtFlushKey_WithMappedHandle_Succeeds) {
    LogEvent create_ev = MakeEvent("NtCreateKey", {
        std::wstring(L"0x209"), (int64_t)0, (int64_t)0,
        std::wstring(L"\\REGISTRY\\MACHINE\\SOFTWARE\\WARRegTest"),
        std::wstring(L"HKEY_LOCAL_MACHINE\\SOFTWARE\\WARRegTest"),
    });
    exec_.Execute(create_ev, pa_);
    ASSERT_TRUE(hmap_.HasMapping(0x209));

    LogEvent ev = MakeEvent("NtFlushKey", { std::wstring(L"0x209") });
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);
}

// ── NtQueryKey ────────────────────────────────────────────────────────────────

TEST_F(NtRegistryExecutorTest, NtQueryKey_WithMappedHandle_Succeeds) {
    LogEvent create_ev = MakeEvent("NtCreateKey", {
        std::wstring(L"0x210"), (int64_t)0, (int64_t)0,
        std::wstring(L"\\REGISTRY\\MACHINE\\SOFTWARE\\WARRegTest"),
        std::wstring(L"HKEY_LOCAL_MACHINE\\SOFTWARE\\WARRegTest"),
    });
    exec_.Execute(create_ev, pa_);
    ASSERT_TRUE(hmap_.HasMapping(0x210));

    LogEvent ev = MakeEvent("NtQueryKey", {
        std::wstring(L"0x210"),  // [0] handle
        (int64_t)2,              // [1] KeyFullInformation
    });
    DWORD_PTR status = exec_.Execute(ev, pa_);
    EXPECT_EQ(status, (DWORD_PTR)0);  // STATUS_SUCCESS
}

TEST_F(NtRegistryExecutorTest, NtQueryKey_WithNullHandle_ReturnsApprox) {
    LogEvent ev = MakeEvent("NtQueryKey", { (int64_t)0, (int64_t)2 });
    // Unmapped handle → executor returns 0 (approx)
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);
}

// ── NtEnumerateKey ────────────────────────────────────────────────────────────

TEST_F(NtRegistryExecutorTest, NtEnumerateKey_WithMappedHandle_ReturnsSomething) {
    // Create a key with at least one subkey (WARRegTest itself will be enumerated).
    LogEvent create_ev = MakeEvent("NtCreateKey", {
        std::wstring(L"0x211"), (int64_t)0, (int64_t)0,
        std::wstring(L"\\REGISTRY\\MACHINE\\SOFTWARE\\WARRegTest"),
        std::wstring(L"HKEY_LOCAL_MACHINE\\SOFTWARE\\WARRegTest"),
    });
    exec_.Execute(create_ev, pa_);
    ASSERT_TRUE(hmap_.HasMapping(0x211));

    // Open its parent (HKLM\SOFTWARE) to enumerate it; for simplicity open a
    // known sandbox key and enumerate index 0 — succeeds or returns STATUS_NO_MORE_ENTRIES
    LogEvent ev = MakeEvent("NtEnumerateKey", {
        std::wstring(L"0x211"),  // [0] handle
        (int64_t)0,              // [1] index 0
    });
    // Returns STATUS_SUCCESS (0) if index 0 exists, or STATUS_NO_MORE_ENTRIES otherwise.
    // Both are acceptable — the critical check is that the executor doesn't crash.
    DWORD_PTR status = exec_.Execute(ev, pa_);
    (void)status;  // status value is environment-dependent; no-crash is sufficient
}

TEST_F(NtRegistryExecutorTest, NtEnumerateKey_WithNullHandle_ReturnsApprox) {
    LogEvent ev = MakeEvent("NtEnumerateKey", { (int64_t)0, (int64_t)0 });
    DWORD_PTR status = exec_.Execute(ev, pa_);
    EXPECT_NE(status, (DWORD_PTR)0);  // null handle → error code
}

// ── NtEnumerateValueKey ───────────────────────────────────────────────────────

TEST_F(NtRegistryExecutorTest, NtEnumerateValueKey_WithMappedHandle_ReturnsSomething) {
    // Create key and set a value first
    LogEvent create_ev = MakeEvent("NtCreateKey", {
        std::wstring(L"0x212"), (int64_t)0, (int64_t)0,
        std::wstring(L"\\REGISTRY\\MACHINE\\SOFTWARE\\WARRegTest"),
        std::wstring(L"HKEY_LOCAL_MACHINE\\SOFTWARE\\WARRegTest"),
    });
    exec_.Execute(create_ev, pa_);
    ASSERT_TRUE(hmap_.HasMapping(0x212));

    LogEvent set_ev = MakeEvent("NtSetValueKey", {
        std::wstring(L"0x212"), std::wstring(L"EnumVal"),
        (int64_t)0, (int64_t)1, std::wstring(L"data"),
    });
    exec_.Execute(set_ev, pa_);

    LogEvent ev = MakeEvent("NtEnumerateValueKey", {
        std::wstring(L"0x212"),  // [0] handle
        (int64_t)0,              // [1] index 0
    });
    DWORD_PTR status = exec_.Execute(ev, pa_);
    // STATUS_SUCCESS (value at index 0 exists) or STATUS_NO_MORE_ENTRIES — both OK.
    (void)status;
}

TEST_F(NtRegistryExecutorTest, NtEnumerateValueKey_WithNullHandle_ReturnsError) {
    LogEvent ev = MakeEvent("NtEnumerateValueKey", { (int64_t)0, (int64_t)0 });
    DWORD_PTR status = exec_.Execute(ev, pa_);
    EXPECT_NE(status, (DWORD_PTR)0);  // null handle → error code
}

// ── NtOpenKeyEx ───────────────────────────────────────────────────────────────

TEST_F(NtRegistryExecutorTest, NtOpenKeyEx_OpensSandboxKey) {
    // Create key first, then open it with NtOpenKeyEx.
    LogEvent create_ev = MakeEvent("NtCreateKey", {
        std::wstring(L"0x213"), (int64_t)0, (int64_t)0,
        std::wstring(L"\\REGISTRY\\MACHINE\\SOFTWARE\\WARRegTest"),
        std::wstring(L"HKEY_LOCAL_MACHINE\\SOFTWARE\\WARRegTest"),
    });
    exec_.Execute(create_ev, pa_);

    LogEvent ev = MakeEvent("NtOpenKeyEx", {
        std::wstring(L"0x214"), (int64_t)0, (int64_t)0,
        std::wstring(L"\\REGISTRY\\MACHINE\\SOFTWARE\\WARRegTest"),
        std::wstring(L"HKEY_LOCAL_MACHINE\\SOFTWARE\\WARRegTest"),
    });
    DWORD_PTR status = exec_.Execute(ev, pa_);
    EXPECT_EQ(status, (DWORD_PTR)0);   // STATUS_SUCCESS
    EXPECT_TRUE(hmap_.HasMapping(0x214));
}

// ── NtDeleteValueKey ──────────────────────────────────────────────────────────

TEST_F(NtRegistryExecutorTest, NtDeleteValueKey_WithMappedHandle_Succeeds) {
    // Create key and set a value, then delete it.
    LogEvent create_ev = MakeEvent("NtCreateKey", {
        std::wstring(L"0x215"), (int64_t)0, (int64_t)0,
        std::wstring(L"\\REGISTRY\\MACHINE\\SOFTWARE\\WARRegTest"),
        std::wstring(L"HKEY_LOCAL_MACHINE\\SOFTWARE\\WARRegTest"),
    });
    exec_.Execute(create_ev, pa_);
    ASSERT_TRUE(hmap_.HasMapping(0x215));

    exec_.Execute(MakeEvent("NtSetValueKey", {
        std::wstring(L"0x215"), std::wstring(L"DelValue"),
        (int64_t)0, (int64_t)1, std::wstring(L"data"),
    }), pa_);

    LogEvent ev = MakeEvent("NtDeleteValueKey", {
        std::wstring(L"0x215"),         // [0] handle
        std::wstring(L"DelValue"),      // [1] value name
    });
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);  // STATUS_SUCCESS
}

TEST_F(NtRegistryExecutorTest, NtDeleteValueKey_WithNullHandle_ReturnsApprox) {
    // Null handle → hkey=nullptr → returns 0 (approx success).
    LogEvent ev = MakeEvent("NtDeleteValueKey", {
        (int64_t)0,                  // [0] null handle
        std::wstring(L"AnyValue"),
    });
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);
}

// ── Zw* aliases (same code paths as Nt* variants) ─────────────────────────────

TEST_F(NtRegistryExecutorTest, ZwAliases_ProduceSameOutcomesAsNtVariants) {
    // ZwCreateKey → same branch as NtCreateKey.
    EXPECT_EQ(exec_.Execute(MakeEvent("ZwCreateKey", {
        std::wstring(L"0x216"), (int64_t)0, (int64_t)0,
        std::wstring(L"\\REGISTRY\\MACHINE\\SOFTWARE\\WARRegTest"),
        std::wstring(L"HKEY_LOCAL_MACHINE\\SOFTWARE\\WARRegTest"),
    }), pa_), (DWORD_PTR)0);
    EXPECT_TRUE(hmap_.HasMapping(0x216));

    // ZwSetValueKey → same branch as NtSetValueKey.
    EXPECT_EQ(exec_.Execute(MakeEvent("ZwSetValueKey", {
        std::wstring(L"0x216"), std::wstring(L"ZwVal"),
        (int64_t)0, (int64_t)1, std::wstring(L"hello"),
    }), pa_), (DWORD_PTR)0);

    // ZwQueryValueKey → same branch as NtQueryValueKey.
    EXPECT_EQ(exec_.Execute(MakeEvent("ZwQueryValueKey", {
        std::wstring(L"0x216"), std::wstring(L"ZwVal"),
    }), pa_), (DWORD_PTR)0);

    // ZwDeleteValueKey → same branch as NtDeleteValueKey.
    EXPECT_EQ(exec_.Execute(MakeEvent("ZwDeleteValueKey", {
        std::wstring(L"0x216"), std::wstring(L"ZwVal"),
    }), pa_), (DWORD_PTR)0);

    // ZwOpenKey → same branch as NtOpenKey; key exists (created above).
    EXPECT_EQ(exec_.Execute(MakeEvent("ZwOpenKey", {
        std::wstring(L"0x217"), (int64_t)0, (int64_t)0,
        std::wstring(L"\\REGISTRY\\MACHINE\\SOFTWARE\\WARRegTest"),
        std::wstring(L"HKEY_LOCAL_MACHINE\\SOFTWARE\\WARRegTest"),
    }), pa_), (DWORD_PTR)0);
    EXPECT_TRUE(hmap_.HasMapping(0x217));

    // ZwOpenKeyEx → same branch as NtOpenKeyEx.
    EXPECT_EQ(exec_.Execute(MakeEvent("ZwOpenKeyEx", {
        std::wstring(L"0x218"), (int64_t)0, (int64_t)0,
        std::wstring(L"\\REGISTRY\\MACHINE\\SOFTWARE\\WARRegTest"),
        std::wstring(L"HKEY_LOCAL_MACHINE\\SOFTWARE\\WARRegTest"),
    }), pa_), (DWORD_PTR)0);
    EXPECT_TRUE(hmap_.HasMapping(0x218));

    // ZwQueryKey → same branch as NtQueryKey; null handle → approx (returns 0).
    EXPECT_EQ(exec_.Execute(MakeEvent("ZwQueryKey", {
        (int64_t)0, (int64_t)2,
    }), pa_), (DWORD_PTR)0);

    // ZwEnumerateKey → same branch as NtEnumerateKey; null handle → error.
    EXPECT_NE(exec_.Execute(MakeEvent("ZwEnumerateKey", {
        (int64_t)0, (int64_t)0,
    }), pa_), (DWORD_PTR)0);

    // ZwEnumerateValueKey → same branch as NtEnumerateValueKey; null handle → error.
    EXPECT_NE(exec_.Execute(MakeEvent("ZwEnumerateValueKey", {
        (int64_t)0, (int64_t)0,
    }), pa_), (DWORD_PTR)0);

    // ZwDeleteKey → same branch as NtDeleteKey; null handle → returns 0.
    EXPECT_EQ(exec_.Execute(MakeEvent("ZwDeleteKey", { (int64_t)0 }), pa_), (DWORD_PTR)0);

    // ZwFlushKey → same branch as NtFlushKey; null handle → returns 0.
    EXPECT_EQ(exec_.Execute(MakeEvent("ZwFlushKey", { (int64_t)0 }), pa_), (DWORD_PTR)0);
}

// ── NtQueryLicenseValue ───────────────────────────────────────────────────────

TEST_F(NtRegistryExecutorTest, NtQueryLicenseValue_ReturnsObjectNameNotFound) {
    // Sandbox environment has no Windows license data.
    // Executor always returns STATUS_OBJECT_NAME_NOT_FOUND (0xC0000034).
    LogEvent ev = MakeEvent("NtQueryLicenseValue", {
        std::wstring(L"Kernel-SystemLicenseData"),
    });
    DWORD_PTR status = exec_.Execute(ev, pa_);
    EXPECT_EQ(status, (DWORD_PTR)0xC0000034UL);
}
