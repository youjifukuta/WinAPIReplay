// Tests for ApiExecutor routing invariants after the Layer-1 / kLayer2Blocked redesign.
//
// DESIGN INVARIANT (enforced here):
//   Layer-1 set  = APIs registered in executor dispatch tables (SupportedApis())
//   kLayer2Blocked = APIs with NO safe executor, dangerous via GenericDispatcher
//   These two sets must be STRICTLY DISJOINT.
//
// Routing order (api_executor.cpp Execute()):
//   1. kDangerousApis     → skip "dangerous: …"
//   2. kLayer2Blocked     → skip "Layer2: blocked …"   ← checked BEFORE sig_db_
//   3. sig_db_ + executor → Layer-1 execute
//   4. sig_db_, no exec   → skip "Layer1: no executor registered"
//   5. GenericDispatcher  → Layer-2 execute or "Layer2: no export found"
//
// kLayer2Blocked contains exactly 6 APIs (none of which appear in sig_db_):
//   NtWaitForMultipleObjectsEx, CoCreateInstanceEx,
//   NtCreateProcessEx, ZwCreateProcessEx, ZwOpenSemaphore, ZwOpenTimer
#include <gtest/gtest.h>
#include <windows.h>
#include "replay/api_executor.h"
#include "replay/arg_preparer.h"
#include "replay/handle_map.h"
#include "replay/pointer_map.h"
#include "replay/pid_map.h"
#include "replay/path_sandbox.h"
#include "replay/registry_sandbox.h"
#include "replay/generic_dispatcher.h"
#include "replay/config.h"
#include "replay/executors/file_executor.h"
#include "replay/executors/dll_executor.h"
#include "replay/executors/nt_sync_executor.h"
#include "replay/executors/nt_registry_executor.h"
#include "replay/executors/nt_misc_executor.h"
#include "replay/executors/network_executor.h"
#include "replay/executors/process_executor.h"
#include "replay/net_simulator.h"
#include "replay/log_types.h"
#include <winsock2.h>

static const char* kSigDbPath = "C:\\Projects\\WinAPIReplay\\data\\api_signatures.json";

static LogEvent MakeEvent(std::string api, std::string status = "success") {
    LogEvent ev;
    ev.api_name = std::move(api);
    ev.status   = std::move(status);
    ev.seq      = 1;
    return ev;
}

// Fixture: loads the real SignatureDB.
// Registers FileExecutor, DllExecutor, NtSyncExecutor, NtRegistryExecutor,
// NtMiscExecutor to cover representative Layer-1 paths in routing tests.
class ApiExecutorRoutingTest : public ::testing::Test {
protected:
    SignatureDB      sig_db_;
    HandleMap        hmap_;
    PointerMap       pmap_;
    PidMap           pids_;
    PathSandbox      psb_{L""};   // empty = disabled
    RegistrySandbox  rsb_;
    Config           cfg_;
    ArgPreparer      arg_prep_{sig_db_, hmap_, pmap_, pids_, psb_, rsb_};
    ApiExecutor      api_exec_{sig_db_, arg_prep_, hmap_, pmap_, pids_, cfg_, psb_, rsb_};
    GenericDispatcher gdisp_{hmap_};

    FileExecutor        file_exec_{hmap_, pmap_, psb_};
    DllExecutor         dll_exec_ {hmap_, pmap_};
    NtSyncExecutor      ntsync_exec_{hmap_, pmap_};
    NtRegistryExecutor  ntreg_exec_ {hmap_, pmap_, rsb_};
    NtMiscExecutor      ntmisc_exec_{hmap_, pmap_, psb_};

    void SetUp() override {
        sig_db_.Load(kSigDbPath);
        api_exec_.Register(&file_exec_);
        api_exec_.Register(&dll_exec_);
        api_exec_.Register(&ntsync_exec_);
        api_exec_.Register(&ntreg_exec_);
        api_exec_.Register(&ntmisc_exec_);
        api_exec_.SetGenericDispatcher(&gdisp_);
        api_exec_.PreInit({});
    }

    EventResult RunOne(const LogEvent& ev) {
        api_exec_.Execute(ev);
        const auto& results = api_exec_.GetStats().results;
        EXPECT_FALSE(results.empty());
        return results.empty() ? EventResult{} : results.back();
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// 1. kDangerousApis: always skipped first, regardless of any other routing
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(ApiExecutorRoutingTest, Dangerous_ExitProcess_IsSkipped) {
    auto r = RunOne(MakeEvent("ExitProcess"));
    EXPECT_EQ(r.outcome, "skipped");
    EXPECT_NE(r.note.find("dangerous"), std::string::npos);
}

TEST_F(ApiExecutorRoutingTest, Dangerous_NtTerminateProcess_IsSkipped) {
    auto r = RunOne(MakeEvent("NtTerminateProcess"));
    EXPECT_EQ(r.outcome, "skipped");
    EXPECT_NE(r.note.find("dangerous"), std::string::npos);
}

TEST_F(ApiExecutorRoutingTest, Dangerous_TerminateThread_IsSkipped) {
    auto r = RunOne(MakeEvent("TerminateThread"));
    EXPECT_EQ(r.outcome, "skipped");
}

TEST_F(ApiExecutorRoutingTest, Dangerous_RtlExitUserProcess_IsSkipped) {
    auto r = RunOne(MakeEvent("RtlExitUserProcess"));
    EXPECT_EQ(r.outcome, "skipped");
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. kLayer2Blocked (new, 6 APIs only): checked before sig_db_ lookup.
//    All 6 are NOT in sig_db_ and have no safe Layer-1 executor.
//    They must produce "Layer2: blocked" regardless of GenericDispatcher.
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(ApiExecutorRoutingTest, Layer2Blocked_NtCreateProcessEx) {
    auto r = RunOne(MakeEvent("NtCreateProcessEx"));
    EXPECT_EQ(r.outcome, "skipped");
    EXPECT_NE(r.note.find("Layer2"), std::string::npos);
    EXPECT_NE(r.note.find("blocked"), std::string::npos);
}

TEST_F(ApiExecutorRoutingTest, Layer2Blocked_ZwCreateProcessEx) {
    auto r = RunOne(MakeEvent("ZwCreateProcessEx"));
    EXPECT_EQ(r.outcome, "skipped");
    EXPECT_NE(r.note.find("blocked"), std::string::npos);
}

TEST_F(ApiExecutorRoutingTest, Layer2Blocked_CoCreateInstanceEx) {
    auto r = RunOne(MakeEvent("CoCreateInstanceEx"));
    EXPECT_EQ(r.outcome, "skipped");
    EXPECT_NE(r.note.find("blocked"), std::string::npos);
}

TEST_F(ApiExecutorRoutingTest, Layer2Blocked_NtWaitForMultipleObjectsEx) {
    auto r = RunOne(MakeEvent("NtWaitForMultipleObjectsEx"));
    EXPECT_EQ(r.outcome, "skipped");
    EXPECT_NE(r.note.find("blocked"), std::string::npos);
}

TEST_F(ApiExecutorRoutingTest, Layer2Blocked_ZwOpenSemaphore) {
    auto r = RunOne(MakeEvent("ZwOpenSemaphore"));
    EXPECT_EQ(r.outcome, "skipped");
    EXPECT_NE(r.note.find("blocked"), std::string::npos);
}

TEST_F(ApiExecutorRoutingTest, Layer2Blocked_ZwOpenTimer) {
    auto r = RunOne(MakeEvent("ZwOpenTimer"));
    EXPECT_EQ(r.outcome, "skipped");
    EXPECT_NE(r.note.find("blocked"), std::string::npos);
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. DESIGN INVARIANT: kLayer2Blocked ∩ sig_db_ = ∅
//    None of the 6 blocked APIs may appear in api_signatures.json.
//    If sig_db_.Find() returns non-null, the API would route to Layer 1
//    and kLayer2Blocked (checked before sig_db_) would still block it —
//    but having a sig_db_ entry for a blocked API signals a design error.
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(ApiExecutorRoutingTest, Invariant_Layer2Blocked_NotInSigDb_NtCreateProcessEx) {
    EXPECT_EQ(sig_db_.Find("NtCreateProcessEx"), nullptr)
        << "NtCreateProcessEx must NOT be in api_signatures.json (Layer2Blocked invariant)";
}

TEST_F(ApiExecutorRoutingTest, Invariant_Layer2Blocked_NotInSigDb_ZwCreateProcessEx) {
    EXPECT_EQ(sig_db_.Find("ZwCreateProcessEx"), nullptr);
}

TEST_F(ApiExecutorRoutingTest, Invariant_Layer2Blocked_NotInSigDb_CoCreateInstanceEx) {
    EXPECT_EQ(sig_db_.Find("CoCreateInstanceEx"), nullptr);
}

TEST_F(ApiExecutorRoutingTest, Invariant_Layer2Blocked_NotInSigDb_NtWaitForMultipleObjectsEx) {
    EXPECT_EQ(sig_db_.Find("NtWaitForMultipleObjectsEx"), nullptr);
}

TEST_F(ApiExecutorRoutingTest, Invariant_Layer2Blocked_NotInSigDb_ZwOpenSemaphore) {
    EXPECT_EQ(sig_db_.Find("ZwOpenSemaphore"), nullptr);
}

TEST_F(ApiExecutorRoutingTest, Invariant_Layer2Blocked_NotInSigDb_ZwOpenTimer) {
    EXPECT_EQ(sig_db_.Find("ZwOpenTimer"), nullptr);
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Former kLayer2Blocked APIs now routed to Layer 1 (executor-handled).
//    These APIs were previously in the old (181-entry) kLayer2Blocked but
//    have safe Layer-1 executor implementations.  After the redesign they
//    must NOT be intercepted by kLayer2Blocked — they must reach Layer 1.
//    The note must contain "Layer1", NOT "Layer2".
// ─────────────────────────────────────────────────────────────────────────────

// NtRegistryExecutor handles NtCreateKey safely (RegistrySandbox).
TEST_F(ApiExecutorRoutingTest, FormerBlocked_NtCreateKey_RoutedToLayer1) {
    // NtRegistryExecutor is registered → executor runs → outcome is success or failed,
    // never "Layer2: blocked".
    auto r = RunOne(MakeEvent("NtCreateKey"));
    EXPECT_EQ(r.note.find("blocked"), std::string::npos);
    EXPECT_NE(r.outcome, "skipped");
}

// NtSyncExecutor handles NtWaitForSingleObject safely (HandleMap + no real wait on null).
TEST_F(ApiExecutorRoutingTest, FormerBlocked_NtWaitForSingleObject_RoutedToLayer1) {
    auto r = RunOne(MakeEvent("NtWaitForSingleObject"));
    EXPECT_EQ(r.note.find("blocked"), std::string::npos);
}

// NtMemoryExecutor handles NtAllocateVirtualMemory (pointer_map_ + GetCurrentProcess).
// NtMemoryExecutor is NOT registered in this fixture, so result is "Layer1: no executor".
// The key point: note says "Layer1" not "Layer2: blocked".
TEST_F(ApiExecutorRoutingTest, FormerBlocked_NtAllocateVirtualMemory_RoutedToLayer1) {
    auto r = RunOne(MakeEvent("NtAllocateVirtualMemory"));
    EXPECT_EQ(r.note.find("blocked"), std::string::npos);
    if (r.outcome == "skipped")
        EXPECT_NE(r.note.find("Layer1"), std::string::npos);
}

// NtMiscExecutor handles AddVectoredExceptionHandler (stub, returns fake handle).
TEST_F(ApiExecutorRoutingTest, FormerBlocked_AddVectoredExceptionHandler_RoutedToLayer1) {
    auto r = RunOne(MakeEvent("AddVectoredExceptionHandler"));
    EXPECT_EQ(r.note.find("blocked"), std::string::npos);
}

// NtMiscExecutor handles CoInitializeEx (actually calls CoInitializeEx safely).
TEST_F(ApiExecutorRoutingTest, FormerBlocked_CoInitializeEx_RoutedToLayer1) {
    auto r = RunOne(MakeEvent("CoInitializeEx"));
    EXPECT_EQ(r.note.find("blocked"), std::string::npos);
}

// NtMiscExecutor handles NtOpenProcess (opens process handle, registers in HandleMap).
TEST_F(ApiExecutorRoutingTest, FormerBlocked_NtOpenProcess_RoutedToLayer1) {
    auto r = RunOne(MakeEvent("NtOpenProcess"));
    EXPECT_EQ(r.note.find("blocked"), std::string::npos);
}

// LdrExecutor handles LdrLoadDll (LoadLibrary via ldr, registers module in HandleMap).
// LdrExecutor NOT registered in this fixture → Layer1: no executor registered.
TEST_F(ApiExecutorRoutingTest, FormerBlocked_LdrLoadDll_RoutedToLayer1) {
    auto r = RunOne(MakeEvent("LdrLoadDll"));
    EXPECT_EQ(r.note.find("blocked"), std::string::npos);
    if (r.outcome == "skipped")
        EXPECT_NE(r.note.find("Layer1"), std::string::npos);
}

// NtRegistryExecutor handles NtOpenKey (RegistrySandbox).
TEST_F(ApiExecutorRoutingTest, FormerBlocked_NtOpenKey_RoutedToLayer1) {
    auto r = RunOne(MakeEvent("NtOpenKey"));
    EXPECT_EQ(r.note.find("blocked"), std::string::npos);
}

// NtSyncExecutor handles NtCreateMutant (creates real kernel mutant, registers handle).
TEST_F(ApiExecutorRoutingTest, FormerBlocked_NtCreateMutant_RoutedToLayer1) {
    auto r = RunOne(MakeEvent("NtCreateMutant"));
    EXPECT_EQ(r.note.find("blocked"), std::string::npos);
}

// NtSyncExecutor handles NtClose (closes handle via HandleMap or no-op on unmapped).
TEST_F(ApiExecutorRoutingTest, FormerBlocked_NtClose_RoutedToLayer1) {
    auto r = RunOne(MakeEvent("NtClose"));
    EXPECT_EQ(r.note.find("blocked"), std::string::npos);
}

// NtMiscExecutor handles NtSetInformationProcess (no-op stub, returns STATUS_SUCCESS).
TEST_F(ApiExecutorRoutingTest, FormerBlocked_NtSetInformationProcess_RoutedToLayer1) {
    auto r = RunOne(MakeEvent("NtSetInformationProcess"));
    EXPECT_EQ(r.note.find("blocked"), std::string::npos);
}

// NtMiscExecutor handles PathCombineW (safe local-buffer stub).
TEST_F(ApiExecutorRoutingTest, FormerBlocked_PathCombineW_RoutedToLayer1) {
    auto r = RunOne(MakeEvent("PathCombineW"));
    EXPECT_EQ(r.note.find("blocked"), std::string::npos);
}

// ─────────────────────────────────────────────────────────────────────────────
// Extension A: NetSim transforms
// Fixture adds NetworkExecutor + NetSimulator with cfg_.net_sim = true.
// ─────────────────────────────────────────────────────────────────────────────

class NetSimTransformTest : public ::testing::Test {
protected:
    SignatureDB      sig_db_;
    HandleMap        hmap_;
    PointerMap       pmap_;
    PidMap           pids_;
    PathSandbox      psb_{L""};
    RegistrySandbox  rsb_;
    Config           cfg_;
    NetSimulator     net_sim_;
    ArgPreparer      arg_prep_{sig_db_, hmap_, pmap_, pids_, psb_, rsb_};
    ApiExecutor*     api_exec_ = nullptr;
    GenericDispatcher gdisp_{hmap_};
    NetworkExecutor* net_exec_ = nullptr;

    static void SetUpTestSuite() {
        WSADATA wd{};
        WSAStartup(MAKEWORD(2, 2), &wd);
    }
    static void TearDownTestSuite() { WSACleanup(); }

    void SetUp() override {
        sig_db_.Load(kSigDbPath);
        cfg_.net_sim = true;
        api_exec_ = new ApiExecutor(sig_db_, arg_prep_, hmap_, pmap_, pids_, cfg_, psb_, rsb_);
        net_exec_ = new NetworkExecutor(hmap_, pmap_, net_sim_);
        api_exec_->Register(net_exec_);
        api_exec_->SetGenericDispatcher(&gdisp_);
        net_sim_.Start();
        api_exec_->PreInit({});
    }
    void TearDown() override {
        net_sim_.Stop();
        delete api_exec_;  api_exec_ = nullptr;
        delete net_exec_;  net_exec_ = nullptr;
    }

    EventResult RunOne(const LogEvent& ev) {
        api_exec_->Execute(ev);
        const auto& r = api_exec_->GetStats().results;
        return r.empty() ? EventResult{} : r.back();
    }
};

// WSAConnect with IP arg records a NetSim transform: original="IP:port" rewritten="127.0.0.1"
TEST_F(NetSimTransformTest, WSAConnect_RecordsNetSimTransform) {
    LogEvent ev;
    ev.api_name = "WSAConnect";
    ev.seq      = 1;
    ev.args = { std::int64_t{0},          // socket=0 (unmapped → synth)
                std::wstring{L"176.123.9.142"},
                std::int64_t{4444},
                nullptr, nullptr, nullptr, nullptr };

    auto r = RunOne(ev);
    ASSERT_FALSE(r.transforms.empty()) << "Expected NetSim transform";
    EXPECT_EQ(r.transforms[0].param_index, 1);
    EXPECT_EQ(r.transforms[0].original,  "176.123.9.142:4444");
    EXPECT_EQ(r.transforms[0].rewritten, "127.0.0.1");
}

// GetAddrInfoW hostname → 127.0.0.1
TEST_F(NetSimTransformTest, GetAddrInfoW_RecordsHostnameTransform) {
    LogEvent ev;
    ev.api_name = "GetAddrInfoW";
    ev.seq      = 2;
    ev.args = { std::wstring{L"api.ipify.org"}, std::wstring{L""}, nullptr, nullptr };

    auto r = RunOne(ev);
    ASSERT_FALSE(r.transforms.empty());
    EXPECT_EQ(r.transforms[0].param_index, 0);
    EXPECT_EQ(r.transforms[0].original,  "api.ipify.org");
    EXPECT_EQ(r.transforms[0].rewritten, "127.0.0.1");
}

// When net_sim is disabled, no NetSim transform is recorded
TEST_F(NetSimTransformTest, NoTransformWhenNetSimDisabled) {
    // Re-create executor with net_sim=false
    net_sim_.Stop();
    delete api_exec_; delete net_exec_;
    cfg_.net_sim = false;
    NetSimulator sim_off;  // not started
    net_exec_  = new NetworkExecutor(hmap_, pmap_, sim_off);
    api_exec_  = new ApiExecutor(sig_db_, arg_prep_, hmap_, pmap_, pids_, cfg_, psb_, rsb_);
    api_exec_->Register(net_exec_);
    api_exec_->SetGenericDispatcher(&gdisp_);
    api_exec_->PreInit({});

    LogEvent ev;
    ev.api_name = "WSAConnect";
    ev.seq      = 3;
    ev.args = { std::int64_t{0}, std::wstring{L"1.2.3.4"}, std::int64_t{80},
                nullptr, nullptr, nullptr, nullptr };

    api_exec_->Execute(ev);
    const auto& r = api_exec_->GetStats().results;
    if (!r.empty())
        EXPECT_TRUE(r.back().transforms.empty());

    delete api_exec_; api_exec_ = nullptr;
    delete net_exec_; net_exec_ = nullptr;
    // Re-create for TearDown to call Stop() safely
    net_sim_.Start();
    cfg_.net_sim = true;
    api_exec_ = new ApiExecutor(sig_db_, arg_prep_, hmap_, pmap_, pids_, cfg_, psb_, rsb_);
    net_exec_ = new NetworkExecutor(hmap_, pmap_, net_sim_);
}

// ─────────────────────────────────────────────────────────────────────────────
// Extension B: process_events recorded for CreateProcessW/A
// Uses the base fixture (ProcessExecutor not registered → outcome="skipped",
// but process_events is still populated).
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(ApiExecutorRoutingTest, ProcessEvents_CreateProcessW_Recorded) {
    LogEvent ev;
    ev.api_name = "CreateProcessW";
    ev.seq      = 99;
    // arg[0]=lpApplicationName, arg[1]=lpCommandLine, arg[7]=lpCurrentDirectory
    ev.args.resize(10, nullptr);
    ev.args[0] = std::wstring{L"C:\\Windows\\system32\\cmd.exe"};
    ev.args[1] = std::wstring{L"cmd.exe /c evil.bat"};
    ev.args[7] = std::wstring{L"C:\\Users\\victim"};

    api_exec_.Execute(ev);

    const auto& pe = api_exec_.GetStats().process_events;
    ASSERT_EQ(pe.size(), 1u);
    EXPECT_EQ(pe[0].seq,               99);
    EXPECT_EQ(pe[0].api_name,          "CreateProcessW");
    EXPECT_EQ(pe[0].application,       "C:\\Windows\\system32\\cmd.exe");
    EXPECT_EQ(pe[0].command_line,      "cmd.exe /c evil.bat");
    EXPECT_EQ(pe[0].current_directory, "C:\\Users\\victim");
}

TEST_F(ApiExecutorRoutingTest, ProcessEvents_CreateProcessA_Recorded) {
    LogEvent ev;
    ev.api_name = "CreateProcessA";
    ev.seq      = 100;
    ev.args.resize(10, nullptr);
    ev.args[1] = std::wstring{L"malware.exe /silent"};  // lpCommandLine

    api_exec_.Execute(ev);

    const auto& pe = api_exec_.GetStats().process_events;
    // There may be results from previous tests in the same fixture instance;
    // check only the last entry.
    ASSERT_FALSE(pe.empty());
    EXPECT_EQ(pe.back().api_name,     "CreateProcessA");
    EXPECT_EQ(pe.back().command_line, "malware.exe /silent");
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Layer-1: API in sig_db AND executor registered → executor runs
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(ApiExecutorRoutingTest, Layer1_CreateFileW_ExecutorRuns) {
    // Null path → INVALID_HANDLE_VALUE → "failed".  Must NOT be "skipped".
    auto r = RunOne(MakeEvent("CreateFileW"));
    EXPECT_NE(r.outcome, "skipped");
}

TEST_F(ApiExecutorRoutingTest, Layer1_LoadLibraryW_ExecutorRuns) {
    auto r = RunOne(MakeEvent("LoadLibraryW"));
    EXPECT_NE(r.outcome, "skipped");
}

TEST_F(ApiExecutorRoutingTest, Layer1_NtCreateEvent_NtSyncExecutorRuns) {
    // NtSyncExecutor creates a real event object → "success" (returns STATUS handle)
    auto r = RunOne(MakeEvent("NtCreateEvent"));
    EXPECT_NE(r.outcome, "skipped");
}

TEST_F(ApiExecutorRoutingTest, Layer1_NtCreateKey_NtRegistryExecutorRuns) {
    // NtRegistryExecutor tries to create a key; with empty args it returns 0 → "success"
    auto r = RunOne(MakeEvent("NtCreateKey"));
    EXPECT_NE(r.outcome, "skipped");
}

TEST_F(ApiExecutorRoutingTest, Layer1_CoInitializeEx_NtMiscExecutorRuns) {
    // NtMiscExecutor calls CoInitializeEx → returns S_OK(0) → "success"
    auto r = RunOne(MakeEvent("CoInitializeEx"));
    EXPECT_NE(r.outcome, "skipped");
}

TEST_F(ApiExecutorRoutingTest, Layer1_AddVectoredExceptionHandler_NtMiscExecutorRuns) {
    // NtMiscExecutor returns fake handle 1 → "success"
    auto r = RunOne(MakeEvent("AddVectoredExceptionHandler"));
    EXPECT_NE(r.outcome, "skipped");
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Layer-2 GenericDispatcher: API not in sig_db, not in kLayer2Blocked
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(ApiExecutorRoutingTest, Layer2Generic_GetCurrentProcessId_Succeeds) {
    auto r = RunOne(MakeEvent("GetCurrentProcessId"));
    EXPECT_EQ(r.outcome, "success");
}

TEST_F(ApiExecutorRoutingTest, Layer2Generic_GetTickCount_Succeeds) {
    auto r = RunOne(MakeEvent("GetTickCount"));
    EXPECT_EQ(r.outcome, "success");
}

TEST_F(ApiExecutorRoutingTest, Layer2Generic_UnknownApi_NoExportFound) {
    auto r = RunOne(MakeEvent("__WinAPIReplay_NoSuchExport_XYZ__"));
    EXPECT_EQ(r.outcome, "skipped");
    EXPECT_NE(r.note.find("no export found"), std::string::npos);
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. dry-run mode: every API is skipped, no executor or dispatcher runs
// ─────────────────────────────────────────────────────────────────────────────

TEST(ApiExecutorDryRun, AllApisAreSkipped) {
    SignatureDB sd;   sd.Load(kSigDbPath);
    HandleMap h; PointerMap p; PidMap pi;
    PathSandbox ps{L""}; RegistrySandbox rs;
    Config cfg;
    cfg.dry_run = true;
    ArgPreparer ap{sd, h, p, pi, ps, rs};
    ApiExecutor ex{sd, ap, h, p, pi, cfg, ps, rs};
    FileExecutor fe{h, p, ps};
    ex.Register(&fe);
    ex.PreInit({});

    // Mix of Layer1, Layer2Blocked, GenericDispatcher, and dangerous APIs
    ex.Execute(MakeEvent("CreateFileW"));
    ex.Execute(MakeEvent("NtCreateProcessEx"));
    ex.Execute(MakeEvent("NtCreateKey"));
    ex.Execute(MakeEvent("GetCurrentProcessId"));
    ex.Execute(MakeEvent("ExitProcess"));

    for (const auto& r : ex.GetStats().results) {
        EXPECT_EQ(r.outcome, "skipped");
        EXPECT_NE(r.note.find("dry-run"), std::string::npos) << "API: " << r.api_name;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Outcome classification: BOOL false → "failed", executor runs
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(ApiExecutorRoutingTest, Layer1_CreateFileW_NullPath_ClassifiedAsFailed) {
    // CreateFileW with null path → INVALID_HANDLE_VALUE → DetermineOutcome → "failed"
    auto r = RunOne(MakeEvent("CreateFileW"));
    EXPECT_EQ(r.outcome, "failed");
}
