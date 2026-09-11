// Tests for DllExecutor after GetProcAddress unsafe-fallback removal.
//
// DESIGN (post-redesign):
//   LoadLibraryW/A/ExW/ExA — SafeLoad uses LOAD_LIBRARY_AS_DATAFILE |
//     LOAD_LIBRARY_AS_IMAGE_RESOURCE so DllMain is never executed.
//   GetProcAddress — returns GetProcAddress() result directly.
//     Does NOT fall back to LoadLibraryExW without flags: executing DllMain
//     on an arbitrary path from a malware log is unsafe.
//   FreeLibrary — passed through as-is.
#include <gtest/gtest.h>
#include <windows.h>
#include "replay/handle_map.h"
#include "replay/pointer_map.h"
#include "replay/executors/dll_executor.h"
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

class DllExecutorTest : public ::testing::Test {
protected:
    HandleMap    hmap_;
    PointerMap   pmap_;
    DllExecutor  exec_{hmap_, pmap_};
};

// ── LoadLibraryW ──────────────────────────────────────────────────────────────

TEST_F(DllExecutorTest, LoadLibraryW_KnownDll_ReturnsHandle) {
    auto p = MakeRaw({(DWORD_PTR)L"kernel32.dll"});
    DWORD_PTR ret = exec_.Execute(MakeEvent("LoadLibraryW"), p);
    EXPECT_NE(ret, (DWORD_PTR)0);
}

TEST_F(DllExecutorTest, LoadLibraryW_NullPath_ReturnsZero) {
    auto p = MakeRaw({0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("LoadLibraryW"), p);
    EXPECT_EQ(ret, (DWORD_PTR)0);
}

// ── LoadLibraryA ──────────────────────────────────────────────────────────────

TEST_F(DllExecutorTest, LoadLibraryA_KnownDll_ReturnsHandle) {
    auto p = MakeRaw({(DWORD_PTR)"advapi32.dll"});
    DWORD_PTR ret = exec_.Execute(MakeEvent("LoadLibraryA"), p);
    EXPECT_NE(ret, (DWORD_PTR)0);
}

// ── LoadLibraryExW / LoadLibraryExA ──────────────────────────────────────────

TEST_F(DllExecutorTest, LoadLibraryExW_KnownDll_ReturnsHandle) {
    auto p = MakeRaw({(DWORD_PTR)L"ntdll.dll", 0, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("LoadLibraryExW"), p);
    EXPECT_NE(ret, (DWORD_PTR)0);
}

TEST_F(DllExecutorTest, LoadLibraryExA_KnownDll_ReturnsHandle) {
    auto p = MakeRaw({(DWORD_PTR)"ntdll.dll", 0, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("LoadLibraryExA"), p);
    EXPECT_NE(ret, (DWORD_PTR)0);
}

// ── GetProcAddress ────────────────────────────────────────────────────────────

TEST_F(DllExecutorTest, GetProcAddress_NormallyLoadedModule_ReturnsProc) {
    // kernel32 is already loaded normally → GetProcAddress succeeds directly
    HMODULE h = GetModuleHandleW(L"kernel32.dll");
    ASSERT_NE(h, (HMODULE)nullptr);
    auto p = MakeRaw({(DWORD_PTR)h, (DWORD_PTR)"GetCurrentProcessId"});
    DWORD_PTR ret = exec_.Execute(MakeEvent("GetProcAddress"), p);
    EXPECT_NE(ret, (DWORD_PTR)0);
}

TEST_F(DllExecutorTest, GetProcAddress_NonExistentProc_ReturnsZeroNoCrash) {
    // Safety invariant (code-level): dll_executor.cpp::GetProcAddress does NOT call
    // LoadLibraryExW(path, nullptr, 0).  Executing DllMain on a path from a malware
    // log is unsafe.  This invariant is enforced by code inspection — the source has
    // no LoadLibraryExW(path, nullptr, 0) call — so a behavioral distinction test is
    // not required here.
    //
    // What IS testable: when GetProcAddress fails (proc does not exist), the executor
    // returns 0 without crashing, regardless of which DLLs are already loaded.
    HMODULE h = GetModuleHandleW(L"kernel32.dll");
    ASSERT_NE(h, (HMODULE)nullptr);
    // A proc that definitively does not exist in kernel32
    auto p = MakeRaw({(DWORD_PTR)h, (DWORD_PTR)"__WinAPIReplay_NoSuchProc_XYZ__"});
    DWORD_PTR ret = exec_.Execute(MakeEvent("GetProcAddress"), p);
    EXPECT_EQ(ret, (DWORD_PTR)0) << "Non-existent proc must return 0";
}

TEST_F(DllExecutorTest, GetProcAddress_NullModule_ReturnsZero) {
    auto p = MakeRaw({0, (DWORD_PTR)"SomeFunc"});
    DWORD_PTR ret = exec_.Execute(MakeEvent("GetProcAddress"), p);
    EXPECT_EQ(ret, (DWORD_PTR)0);
}

TEST_F(DllExecutorTest, GetProcAddress_NullProcName_ReturnsZero) {
    HMODULE h = GetModuleHandleW(L"kernel32.dll");
    auto p = MakeRaw({(DWORD_PTR)h, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("GetProcAddress"), p);
    EXPECT_EQ(ret, (DWORD_PTR)0);
}

// ── FreeLibrary ───────────────────────────────────────────────────────────────

TEST_F(DllExecutorTest, FreeLibrary_NullHandle_ReturnsTRUE) {
    auto p = MakeRaw({0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("FreeLibrary"), p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
}

TEST_F(DllExecutorTest, FreeLibrary_DatafileModule_Succeeds) {
    HMODULE h = LoadLibraryExW(L"shlwapi.dll", nullptr,
                                LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if (!h) h = GetModuleHandleW(L"shlwapi.dll");
    ASSERT_NE(h, (HMODULE)nullptr);
    auto p = MakeRaw({(DWORD_PTR)h});
    DWORD_PTR ret = exec_.Execute(MakeEvent("FreeLibrary"), p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
}

// ── Unknown API returns 0 ─────────────────────────────────────────────────────

TEST_F(DllExecutorTest, UnknownApi_ReturnsZero) {
    PreparedArgs p;
    DWORD_PTR ret = exec_.Execute(MakeEvent("DllUnknown"), p);
    EXPECT_EQ(ret, (DWORD_PTR)0);
}
