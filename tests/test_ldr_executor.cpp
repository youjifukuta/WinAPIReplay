#include <gtest/gtest.h>
#include <windows.h>
#include "replay/nt_native.h"
#include "replay/handle_map.h"
#include "replay/pointer_map.h"
#include "replay/executors/ldr_executor.h"
#include "replay/log_types.h"
#include "replay/arg_preparer.h"

static LogEvent MakeEvent(std::string api,
                           std::initializer_list<ArgValue> args) {
    LogEvent ev;
    ev.api_name = std::move(api);
    ev.args.assign(args);
    return ev;
}

class LdrExecutorTest : public ::testing::Test {
protected:
    HandleMap    hmap_;
    PointerMap   pmap_;
    LdrExecutor  exec_{hmap_, pmap_};
    PreparedArgs pa_{};

    static void SetUpTestSuite() { NtApiLoad(GetNtApi()); }
};

// ── LdrLoadDll ────────────────────────────────────────────────────────────────

TEST_F(LdrExecutorTest, LdrLoadDll_LoadsKnownDll) {
    // version.dll is a safe, small DLL that is not already loaded by default.
    LogEvent ev = MakeEvent("LdrLoadDll", {
        std::wstring(L"0x500"),       // [0] out DllBase handle
        (int64_t)0,                    // [1] SearchPath (nullptr)
        std::wstring(L"version.dll"), // [2] DLL name
    });
    DWORD_PTR status = exec_.Execute(ev, pa_);
    EXPECT_EQ(status, (DWORD_PTR)0);  // STATUS_SUCCESS
    EXPECT_TRUE(hmap_.HasMapping(0x500));
}

TEST_F(LdrExecutorTest, LdrLoadDll_UnknownDll_FailsWithoutFallback) {
    // The redesign uses a single LdrLoadDll call — no LoadLibraryExW fallback.
    // An unknown DLL name must return a failure NTSTATUS.
    LogEvent ev = MakeEvent("LdrLoadDll", {
        std::wstring(L"0x501"),
        (int64_t)0,
        std::wstring(L"war_nonexistent_12345.dll"),
    });
    DWORD_PTR status = exec_.Execute(ev, pa_);
    EXPECT_NE(status, (DWORD_PTR)0);  // STATUS_DLL_NOT_FOUND (0xC0000135) or similar
    EXPECT_FALSE(hmap_.HasMapping(0x501));
}

// ── LdrGetDllHandle ───────────────────────────────────────────────────────────

TEST_F(LdrExecutorTest, LdrGetDllHandle_FindsAlreadyLoadedDll) {
    // kernel32.dll is guaranteed to be loaded in every Windows process.
    LogEvent ev = MakeEvent("LdrGetDllHandle", {
        std::wstring(L"0x502"),          // [0] out DllBase
        std::wstring(L"kernel32.dll"),   // [1] name
    });
    DWORD_PTR status = exec_.Execute(ev, pa_);
    EXPECT_EQ(status, (DWORD_PTR)0);    // STATUS_SUCCESS
    EXPECT_TRUE(hmap_.HasMapping(0x502));
}

TEST_F(LdrExecutorTest, LdrGetDllHandle_UnknownDll_FailsWithoutFallback) {
    // Single LdrGetDllHandle call only — no LoadLibraryExW fallback.
    LogEvent ev = MakeEvent("LdrGetDllHandle", {
        std::wstring(L"0x503"),
        std::wstring(L"war_nonexistent_12345.dll"),
    });
    DWORD_PTR status = exec_.Execute(ev, pa_);
    EXPECT_NE(status, (DWORD_PTR)0);    // must fail
    EXPECT_FALSE(hmap_.HasMapping(0x503));
}

// ── LdrGetDllHandleByName ─────────────────────────────────────────────────────

TEST_F(LdrExecutorTest, LdrGetDllHandleByName_FindsLoadedDll) {
    // Same branch as LdrGetDllHandle/Ex; ntdll.dll is always loaded.
    LogEvent ev = MakeEvent("LdrGetDllHandleByName", {
        std::wstring(L"0x506"),       // [0] out DllBase
        std::wstring(L"ntdll.dll"),   // [1] name
    });
    DWORD_PTR status = exec_.Execute(ev, pa_);
    EXPECT_EQ(status, (DWORD_PTR)0);   // STATUS_SUCCESS
    EXPECT_TRUE(hmap_.HasMapping(0x506));
}

// ── LdrGetDllHandleEx ─────────────────────────────────────────────────────────

TEST_F(LdrExecutorTest, LdrGetDllHandleEx_FindsLoadedDll) {
    LogEvent ev = MakeEvent("LdrGetDllHandleEx", {
        std::wstring(L"0x504"),         // [0] out DllBase
        std::wstring(L"ntdll.dll"),     // [1] name
    });
    DWORD_PTR status = exec_.Execute(ev, pa_);
    EXPECT_EQ(status, (DWORD_PTR)0);
    EXPECT_TRUE(hmap_.HasMapping(0x504));
}

// ── LdrGetProcedureAddressForCaller ───────────────────────────────────────────

TEST_F(LdrExecutorTest, LdrGetProcedureAddressForCaller_FindsExport) {
    // First, get a handle to kernel32.dll via LdrGetDllHandle.
    LogEvent get_ev = MakeEvent("LdrGetDllHandle", {
        std::wstring(L"0x505"),
        std::wstring(L"kernel32.dll"),
    });
    exec_.Execute(get_ev, pa_);
    ASSERT_TRUE(hmap_.HasMapping(0x505));

    // Then look up a known export.
    LogEvent ev = MakeEvent("LdrGetProcedureAddressForCaller", {
        std::wstring(L"0x505"),            // [0] module handle
        std::wstring(L"GetModuleHandleW"), // [1] proc name
        std::wstring(L"0x80000000"),       // [2] out proc addr
    });
    DWORD_PTR status = exec_.Execute(ev, pa_);
    EXPECT_EQ(status, (DWORD_PTR)0);
    EXPECT_NE(pmap_.Resolve((DWORD_PTR)0x80000000), (DWORD_PTR)0x80000000);
}

TEST_F(LdrExecutorTest, LdrGetProcedureAddressForCaller_UnmappedModule_FailsGracefully) {
    // 0x9AB is not in handle_map_ → executor returns STATUS_PROCEDURE_NOT_FOUND.
    LogEvent ev = MakeEvent("LdrGetProcedureAddressForCaller", {
        std::wstring(L"0x9AB"),
        std::wstring(L"SomeExport"),
        std::wstring(L"0x90000000"),
    });
    DWORD_PTR status = exec_.Execute(ev, pa_);
    EXPECT_NE(status, (DWORD_PTR)0);
    EXPECT_EQ(pmap_.Resolve((DWORD_PTR)0x90000000), (DWORD_PTR)0x90000000);
}
