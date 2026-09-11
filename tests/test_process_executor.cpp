// Tests for ProcessExecutor: all 15 APIs in SupportedApis().
// ProcessExecutor uses p.raw[] for args.  All tests run with no_spawn_=true
// to avoid creating child processes inside the test harness.
#include <gtest/gtest.h>
#include <windows.h>
#include "replay/handle_map.h"
#include "replay/pointer_map.h"
#include "replay/pid_map.h"
#include "replay/executors/process_executor.h"
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

class ProcessExecutorTest : public ::testing::Test {
protected:
    HandleMap       hmap_;
    PointerMap      pmap_;
    PidMap          pids_;
    // no_spawn_=true: CreateProcess/Thread return synthesized handles
    ProcessExecutor exec_{hmap_, pmap_, pids_, true};
};

// ── CreateProcessW (no_spawn) ─────────────────────────────────────────────────

TEST_F(ProcessExecutorTest, CreateProcessW_NoSpawn_ReturnsTRUE) {
    PROCESS_INFORMATION pi{};
    PreparedArgs p;
    p.raw.resize(10, 0);
    p.args.resize(10);
    p.raw[9] = (DWORD_PTR)&pi;
    DWORD_PTR ret = exec_.Execute(MakeEvent("CreateProcessW"), p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
    // With no_spawn_ the executor fills pi with current process handles
    EXPECT_NE(pi.hProcess, (HANDLE)nullptr);
}

// ── CreateProcessA (no_spawn) ─────────────────────────────────────────────────

TEST_F(ProcessExecutorTest, CreateProcessA_NoSpawn_ReturnsTRUE) {
    PROCESS_INFORMATION pi{};
    PreparedArgs p;
    p.raw.resize(10, 0);
    p.args.resize(10);
    p.raw[9] = (DWORD_PTR)&pi;
    DWORD_PTR ret = exec_.Execute(MakeEvent("CreateProcessA"), p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
}

// ── OpenProcess ───────────────────────────────────────────────────────────────

TEST_F(ProcessExecutorTest, OpenProcess_CurrentPid_ReturnsHandle) {
    auto p = MakeRaw({PROCESS_QUERY_INFORMATION, FALSE, (DWORD_PTR)GetCurrentProcessId()});
    DWORD_PTR ret = exec_.Execute(MakeEvent("OpenProcess"), p);
    EXPECT_NE(ret, (DWORD_PTR)0);
    HANDLE h = (HANDLE)ret;
    if (h) CloseHandle(h);
}

TEST_F(ProcessExecutorTest, OpenProcess_ZeroPid_OpensCurrentProcess) {
    // PID=0 → executor substitutes current process ID
    auto p = MakeRaw({PROCESS_QUERY_INFORMATION, FALSE, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("OpenProcess"), p);
    EXPECT_NE(ret, (DWORD_PTR)0);
    HANDLE h = (HANDLE)ret;
    if (h) CloseHandle(h);
}

// ── TerminateProcess ──────────────────────────────────────────────────────────

TEST_F(ProcessExecutorTest, TerminateProcess_AlwaysReturnsTRUE) {
    // Never actually terminates; returns TRUE unconditionally
    auto p = MakeRaw({(DWORD_PTR)GetCurrentProcess(), 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("TerminateProcess"), p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
}

// ── GetExitCodeProcess ────────────────────────────────────────────────────────

TEST_F(ProcessExecutorTest, GetExitCodeProcess_ValidHandle_Succeeds) {
    DWORD code = 0xdeadbeef;
    auto p = MakeRaw({(DWORD_PTR)GetCurrentProcess(), (DWORD_PTR)&code});
    DWORD_PTR ret = exec_.Execute(MakeEvent("GetExitCodeProcess"), p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
}

TEST_F(ProcessExecutorTest, GetExitCodeProcess_NullHandle_Succeeds) {
    auto p = MakeRaw({0, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("GetExitCodeProcess"), p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
}

// ── VirtualAlloc ──────────────────────────────────────────────────────────────

TEST_F(ProcessExecutorTest, VirtualAlloc_AllocatesMemory) {
    // raw[0]=ignored(address), raw[1]=size, raw[2]=type, raw[3]=protect
    auto p = MakeRaw({0, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE});
    DWORD_PTR ret = exec_.Execute(MakeEvent("VirtualAlloc"), p);
    EXPECT_NE(ret, (DWORD_PTR)0);
    void* ptr = (void*)ret;
    if (ptr) VirtualFree(ptr, 0, MEM_RELEASE);
}

// ── VirtualAllocEx ────────────────────────────────────────────────────────────

TEST_F(ProcessExecutorTest, VirtualAllocEx_AllocatesInCurrentProcess) {
    auto p = MakeRaw({(DWORD_PTR)GetCurrentProcess(), 0,
                      4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE});
    DWORD_PTR ret = exec_.Execute(MakeEvent("VirtualAllocEx"), p);
    EXPECT_NE(ret, (DWORD_PTR)0);
    void* ptr = (void*)ret;
    if (ptr) VirtualFree(ptr, 0, MEM_RELEASE);
}

// ── VirtualFree ───────────────────────────────────────────────────────────────

TEST_F(ProcessExecutorTest, VirtualFree_AlwaysReturnsTRUE) {
    // VirtualFree always returns TRUE (no-op: avoids double-free with PointerMap)
    void* addr = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(addr, nullptr);
    auto p = MakeRaw({(DWORD_PTR)addr, 0, MEM_RELEASE});
    DWORD_PTR ret = exec_.Execute(MakeEvent("VirtualFree"), p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
    // Actually free the memory since VirtualFree in executor is a no-op
    VirtualFree(addr, 0, MEM_RELEASE);
}

// ── VirtualProtect ────────────────────────────────────────────────────────────

TEST_F(ProcessExecutorTest, VirtualProtect_NullAddress_ReturnsTRUE) {
    // null address → executor treats as no-op success
    auto p = MakeRaw({0, 4096, PAGE_READWRITE, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("VirtualProtect"), p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
}

TEST_F(ProcessExecutorTest, VirtualProtect_ValidAddress_Succeeds) {
    void* addr = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(addr, nullptr);
    DWORD old = 0;
    auto p = MakeRaw({(DWORD_PTR)addr, 4096, PAGE_READONLY, (DWORD_PTR)&old});
    DWORD_PTR ret = exec_.Execute(MakeEvent("VirtualProtect"), p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
    VirtualFree(addr, 0, MEM_RELEASE);
}

// ── WriteProcessMemory (no_spawn) ─────────────────────────────────────────────

TEST_F(ProcessExecutorTest, WriteProcessMemory_NoSpawn_ReturnsTRUE) {
    auto p = MakeRaw({0, 0, 0, 16, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("WriteProcessMemory"), p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
}

// ── ReadProcessMemory (no_spawn) ──────────────────────────────────────────────

TEST_F(ProcessExecutorTest, ReadProcessMemory_NoSpawn_ReturnsTRUE) {
    auto p = MakeRaw({0, 0, 0, 16, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("ReadProcessMemory"), p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
}

// ── CreateThread (no_spawn) ───────────────────────────────────────────────────

TEST_F(ProcessExecutorTest, CreateThread_NoSpawn_ReturnsHandle) {
    DWORD tid = 0;
    auto p = MakeRaw({0, 4096, 0, 0, CREATE_SUSPENDED, (DWORD_PTR)&tid});
    DWORD_PTR ret = exec_.Execute(MakeEvent("CreateThread"), p);
    HANDLE h = (HANDLE)ret;
    EXPECT_NE(h, (HANDLE)nullptr);
    EXPECT_NE(h, INVALID_HANDLE_VALUE);
    // With no_spawn_ executor creates a real suspended dummy thread
    if (h && h != GetCurrentThread()) {
        TerminateThread(h, 0);
        CloseHandle(h);
    }
}

// ── CreateRemoteThread (no_spawn) ─────────────────────────────────────────────

TEST_F(ProcessExecutorTest, CreateRemoteThread_NoSpawn_ReturnsCurrentThread) {
    auto p = MakeRaw({0, 0, 0, 0, 0, 0, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("CreateRemoteThread"), p);
    EXPECT_NE(ret, (DWORD_PTR)0);
}

// ── QueueUserAPC ──────────────────────────────────────────────────────────────

TEST_F(ProcessExecutorTest, QueueUserAPC_AlwaysReturnsTRUE) {
    auto p = MakeRaw({0, 0, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("QueueUserAPC"), p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
}

// ── NtUnmapViewOfSection ──────────────────────────────────────────────────────

TEST_F(ProcessExecutorTest, NtUnmapViewOfSection_ReturnsSuccess) {
    // Always returns 0 (STATUS_SUCCESS) regardless of args
    auto p = MakeRaw({0, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("NtUnmapViewOfSection"), p);
    EXPECT_EQ(ret, (DWORD_PTR)0);
}

// ── Unknown API returns 0 ─────────────────────────────────────────────────────

TEST_F(ProcessExecutorTest, UnknownApi_ReturnsZero) {
    PreparedArgs p;
    DWORD_PTR ret = exec_.Execute(MakeEvent("ProcessUnknown"), p);
    EXPECT_EQ(ret, (DWORD_PTR)0);
}
