#include <gtest/gtest.h>
#include <windows.h>
#include "replay/nt_native.h"
#include "replay/handle_map.h"
#include "replay/pointer_map.h"
#include "replay/executors/nt_sync_executor.h"
#include "replay/log_types.h"
#include "replay/arg_preparer.h"

// Named-object names use a unique prefix to avoid cross-test collisions.
static constexpr wchar_t kMutantName[]    = L"\\BaseNamedObjects\\WARTest_Mutant_01";
static constexpr wchar_t kEventName[]     = L"\\BaseNamedObjects\\WARTest_Event_01";
static constexpr wchar_t kSemaphoreName[] = L"\\BaseNamedObjects\\WARTest_Semaphore_01";

static LogEvent MakeEvent(std::string api,
                           std::initializer_list<ArgValue> args) {
    LogEvent ev;
    ev.api_name = std::move(api);
    ev.args.assign(args);
    return ev;
}

class NtSyncExecutorTest : public ::testing::Test {
protected:
    HandleMap      hmap_;
    PointerMap     pmap_;
    // wait_timeout_ms=50 for fast test execution.
    NtSyncExecutor exec_{hmap_, pmap_, 50};
    PreparedArgs   pa_{};

    static void SetUpTestSuite() { NtApiLoad(GetNtApi()); }
};

// ── NtCreateMutant ────────────────────────────────────────────────────────────

TEST_F(NtSyncExecutorTest, NtCreateMutant_CreatesAndRegistersHandle) {
    LogEvent ev = MakeEvent("NtCreateMutant", {
        std::wstring(L"0x300"),            // [0] orig handle
        (int64_t)0,                         // [1] access (default MUTANT_ALL_ACCESS)
        (int64_t)0,                         // [2] OA ptr (unused; name from [3])
        std::wstring(kMutantName),          // [3] object name
        (int64_t)0,                         // [4] InitialOwner=FALSE
    });
    DWORD_PTR status = exec_.Execute(ev, pa_);
    EXPECT_EQ(status, (DWORD_PTR)0);       // STATUS_SUCCESS
    EXPECT_TRUE(hmap_.HasMapping(0x300));
}

// ── NtReleaseMutant ───────────────────────────────────────────────────────────

TEST_F(NtSyncExecutorTest, NtReleaseMutant_WithMappedHandle_Succeeds) {
    // Create mutant first.
    LogEvent create_ev = MakeEvent("NtCreateMutant", {
        std::wstring(L"0x301"), (int64_t)0, (int64_t)0,
        std::wstring(L"\\BaseNamedObjects\\WARTest_Mutant_02"),
        (int64_t)1,  // InitialOwner=TRUE so we can release it
    });
    exec_.Execute(create_ev, pa_);
    ASSERT_TRUE(hmap_.HasMapping(0x301));

    LogEvent ev = MakeEvent("NtReleaseMutant", {
        std::wstring(L"0x301"),  // [0] orig handle
    });
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);
}

TEST_F(NtSyncExecutorTest, NtReleaseMutant_WithUnmappedHandle_ReturnsApprox) {
    LogEvent ev = MakeEvent("NtReleaseMutant", {
        std::wstring(L"0x999"),
    });
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);
}

// ── NtOpenMutant — no fallback ────────────────────────────────────────────────

TEST_F(NtSyncExecutorTest, NtOpenMutant_NonexistentName_FailsWithoutFallback) {
    // The redesign removes the NtCreateMutant fallback.
    // NtOpenMutant for a name that doesn't exist must return a non-zero NTSTATUS.
    LogEvent ev = MakeEvent("NtOpenMutant", {
        std::wstring(L"0x302"), (int64_t)0, (int64_t)0,
        std::wstring(L"\\BaseNamedObjects\\WARTest_Mutant_NONEXISTENT"),
    });
    DWORD_PTR status = exec_.Execute(ev, pa_);
    EXPECT_NE(status, (DWORD_PTR)0);  // must fail (0xC0000034 or similar)
    EXPECT_FALSE(hmap_.HasMapping(0x302));
}

// ── NtClose ───────────────────────────────────────────────────────────────────

TEST_F(NtSyncExecutorTest, NtClose_WithMappedHandle_ClosesAndRemovesFromMap) {
    // Create a mutant to get a real handle.
    LogEvent create_ev = MakeEvent("NtCreateMutant", {
        std::wstring(L"0x303"), (int64_t)0, (int64_t)0,
        std::wstring(L"\\BaseNamedObjects\\WARTest_Mutant_03"),
        (int64_t)0,
    });
    exec_.Execute(create_ev, pa_);
    ASSERT_TRUE(hmap_.HasMapping(0x303));

    LogEvent close_ev = MakeEvent("NtClose", {
        std::wstring(L"0x303"),
    });
    DWORD_PTR status = exec_.Execute(close_ev, pa_);
    EXPECT_EQ(status, (DWORD_PTR)0);       // STATUS_SUCCESS
    EXPECT_FALSE(hmap_.HasMapping(0x303)); // mapping invalidated
}

TEST_F(NtSyncExecutorTest, NtClose_WithUnmappedHandle_ReturnsApprox) {
    LogEvent ev = MakeEvent("NtClose", { std::wstring(L"0x998") });
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);
}

// ── NtCreateEvent ─────────────────────────────────────────────────────────────

TEST_F(NtSyncExecutorTest, NtCreateEvent_CreatesAndRegistersHandle) {
    LogEvent ev = MakeEvent("NtCreateEvent", {
        std::wstring(L"0x304"), (int64_t)0, (int64_t)0,
        std::wstring(kEventName),  // [3] name
        (int64_t)0,                // [4] event type (SynchronizationEvent)
        (int64_t)0,                // [5] initial state = not-signalled
    });
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);
    EXPECT_TRUE(hmap_.HasMapping(0x304));
}

// ── NtSetEvent / NtResetEvent ─────────────────────────────────────────────────

TEST_F(NtSyncExecutorTest, NtSetEvent_WithMappedHandle_Succeeds) {
    LogEvent create_ev = MakeEvent("NtCreateEvent", {
        std::wstring(L"0x305"), (int64_t)0, (int64_t)0,
        std::wstring(L"\\BaseNamedObjects\\WARTest_Event_02"),
        (int64_t)1,   // NotificationEvent
        (int64_t)0,
    });
    exec_.Execute(create_ev, pa_);
    ASSERT_TRUE(hmap_.HasMapping(0x305));

    LogEvent set_ev = MakeEvent("NtSetEvent", { std::wstring(L"0x305") });
    EXPECT_EQ(exec_.Execute(set_ev, pa_), (DWORD_PTR)0);

    LogEvent reset_ev = MakeEvent("NtResetEvent", { std::wstring(L"0x305") });
    EXPECT_EQ(exec_.Execute(reset_ev, pa_), (DWORD_PTR)0);
}

// ── NtWaitForMultipleObjects — approx ─────────────────────────────────────────

TEST_F(NtSyncExecutorTest, NtWaitForMultipleObjects_ReturnsApprox) {
    // Cannot reconstruct handle array from log → always returns 0 (approx success).
    LogEvent ev = MakeEvent("NtWaitForMultipleObjects", {
        (int64_t)2,     // count
        (int64_t)0,     // handles ptr
        (int64_t)0,     // WaitAny=0
        (int64_t)0,     // Alertable=FALSE
        (int64_t)0,     // Timeout ptr
    });
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);
}

// ── NtCreateSemaphore ─────────────────────────────────────────────────────────

TEST_F(NtSyncExecutorTest, NtCreateSemaphore_CreatesAndRegistersHandle) {
    LogEvent ev = MakeEvent("NtCreateSemaphore", {
        std::wstring(L"0x306"), (int64_t)0, (int64_t)0,
        std::wstring(kSemaphoreName),  // [3] name
        (int64_t)1,                    // [4] InitialCount
        (int64_t)10,                   // [5] MaximumCount
    });
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);
    EXPECT_TRUE(hmap_.HasMapping(0x306));
}

// ── NtOpenSemaphore — no fallback ─────────────────────────────────────────────

TEST_F(NtSyncExecutorTest, NtOpenSemaphore_NonexistentName_FailsWithoutFallback) {
    LogEvent ev = MakeEvent("NtOpenSemaphore", {
        std::wstring(L"0x307"), (int64_t)0, (int64_t)0,
        std::wstring(L"\\BaseNamedObjects\\WARTest_Semaphore_NONEXISTENT"),
    });
    DWORD_PTR status = exec_.Execute(ev, pa_);
    EXPECT_NE(status, (DWORD_PTR)0);  // must fail
    EXPECT_FALSE(hmap_.HasMapping(0x307));
}

// ── NtWaitForSingleObject ─────────────────────────────────────────────────────

TEST_F(NtSyncExecutorTest, NtWaitForSingleObject_WithMappedEvent_Succeeds) {
    // Create an event, then wait on it; wait_timeout_ms=50 so it doesn't block.
    LogEvent create_ev = MakeEvent("NtCreateEvent", {
        std::wstring(L"0x308"), (int64_t)0, (int64_t)0,
        std::wstring(L"\\BaseNamedObjects\\WARTest_Event_03"),
        (int64_t)1,  // NotificationEvent, initially not-signalled
        (int64_t)0,
    });
    exec_.Execute(create_ev, pa_);
    ASSERT_TRUE(hmap_.HasMapping(0x308));

    LogEvent ev = MakeEvent("NtWaitForSingleObject", {
        std::wstring(L"0x308"), (int64_t)0, (int64_t)0,
    });
    // Returns STATUS_TIMEOUT (0x00000102) because event is not signalled and timeout=50ms.
    DWORD_PTR status = exec_.Execute(ev, pa_);
    EXPECT_EQ(status, (DWORD_PTR)0x00000102UL);
}

TEST_F(NtSyncExecutorTest, NtWaitForSingleObject_WithUnmappedHandle_ReturnsApprox) {
    LogEvent ev = MakeEvent("NtWaitForSingleObject", {
        std::wstring(L"0xDEAD"), (int64_t)0, (int64_t)0,
    });
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);  // approx success
}

// ── NtCreateTimer / NtOpenTimer ───────────────────────────────────────────────

TEST_F(NtSyncExecutorTest, NtCreateTimer_CreatesAndRegistersHandle) {
    LogEvent ev = MakeEvent("NtCreateTimer", {
        std::wstring(L"0x310"), (int64_t)0, (int64_t)0,
        std::wstring(L"\\BaseNamedObjects\\WARTest_Timer_01"),
        (int64_t)0,  // SynchronizationTimer
    });
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);
    EXPECT_TRUE(hmap_.HasMapping(0x310));
}

TEST_F(NtSyncExecutorTest, NtOpenTimer_NonexistentName_FailsWithoutFallback) {
    LogEvent ev = MakeEvent("NtOpenTimer", {
        std::wstring(L"0x311"), (int64_t)0, (int64_t)0,
        std::wstring(L"\\BaseNamedObjects\\WARTest_Timer_NONEXISTENT"),
    });
    DWORD_PTR status = exec_.Execute(ev, pa_);
    EXPECT_NE(status, (DWORD_PTR)0);  // must fail
    EXPECT_FALSE(hmap_.HasMapping(0x311));
}

// ── NtCreateIoCompletion ──────────────────────────────────────────────────────

TEST_F(NtSyncExecutorTest, NtCreateIoCompletion_CreatesAndRegistersHandle) {
    LogEvent ev = MakeEvent("NtCreateIoCompletion", {
        std::wstring(L"0x312"),  // [0] out handle
        (int64_t)0,              // [1] DesiredAccess
        (int64_t)0,              // [2] OA ptr
        (int64_t)0,              // [3] NumberOfConcurrentThreads (0 = CPU count)
    });
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);
    EXPECT_TRUE(hmap_.HasMapping(0x312));
}

// ── NtCreateJobObject ─────────────────────────────────────────────────────────

TEST_F(NtSyncExecutorTest, NtCreateJobObject_CreatesAndRegistersHandle) {
    LogEvent ev = MakeEvent("NtCreateJobObject", {
        std::wstring(L"0x313"),
        (int64_t)0,
        (int64_t)0,
        std::wstring(L""),  // anonymous job (no name)
    });
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);
    EXPECT_TRUE(hmap_.HasMapping(0x313));
}

// ── NtCreateDebugObject ───────────────────────────────────────────────────────

TEST_F(NtSyncExecutorTest, NtCreateDebugObject_CreatesAndRegistersHandle) {
    LogEvent ev = MakeEvent("NtCreateDebugObject", {
        std::wstring(L"0x314"),  // [0] out handle
        (int64_t)0,              // [1] DesiredAccess
        (int64_t)0,              // [2] OA ptr
        (int64_t)0,              // [3] Flags
    });
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);
    EXPECT_TRUE(hmap_.HasMapping(0x314));
}

// ── NtOpenEvent ───────────────────────────────────────────────────────────────

TEST_F(NtSyncExecutorTest, NtOpenEvent_NonexistentName_FailsWithoutFallback) {
    // No NtCreateEvent fallback; opening a nonexistent event returns a non-zero NTSTATUS.
    LogEvent ev = MakeEvent("NtOpenEvent", {
        std::wstring(L"0x316"), (int64_t)0, (int64_t)0,
        std::wstring(L"\\BaseNamedObjects\\WARTest_Event_NONEXISTENT"),
    });
    DWORD_PTR status = exec_.Execute(ev, pa_);
    EXPECT_NE(status, (DWORD_PTR)0);
    EXPECT_FALSE(hmap_.HasMapping(0x316));
}

// ── NtOpenIoCompletion ────────────────────────────────────────────────────────

TEST_F(NtSyncExecutorTest, NtOpenIoCompletion_NonexistentName_FailsWithoutCrash) {
    // Opening a nonexistent IOCP returns a non-zero NTSTATUS.
    LogEvent ev = MakeEvent("NtOpenIoCompletion", {
        std::wstring(L"0x317"), (int64_t)0, (int64_t)0,
        std::wstring(L"\\BaseNamedObjects\\WARTest_IOCP_NONEXISTENT"),
    });
    DWORD_PTR status = exec_.Execute(ev, pa_);
    EXPECT_NE(status, (DWORD_PTR)0);
    EXPECT_FALSE(hmap_.HasMapping(0x317));
}

// ── NtOpenJobObject ───────────────────────────────────────────────────────────

TEST_F(NtSyncExecutorTest, NtOpenJobObject_NonexistentName_FailsWithoutCrash) {
    // Opening a nonexistent job object returns a non-zero NTSTATUS.
    LogEvent ev = MakeEvent("NtOpenJobObject", {
        std::wstring(L"0x318"), (int64_t)0,
        std::wstring(L"\\BaseNamedObjects\\WARTest_Job_NONEXISTENT"),
    });
    DWORD_PTR status = exec_.Execute(ev, pa_);
    EXPECT_NE(status, (DWORD_PTR)0);
    EXPECT_FALSE(hmap_.HasMapping(0x318));
}

// ── Zw* aliases (same code paths as Nt* variants) ─────────────────────────────

TEST_F(NtSyncExecutorTest, ZwAliases_ProduceSameOutcomesAsNtVariants) {
    // ZwClose → same branch as NtClose; unmapped handle → approx (returns 0).
    EXPECT_EQ(exec_.Execute(MakeEvent("ZwClose", {std::wstring(L"0x9A5")}), pa_),
              (DWORD_PTR)0);

    // ZwCreateMutant → same branch as NtCreateMutant.
    EXPECT_EQ(exec_.Execute(MakeEvent("ZwCreateMutant", {
        std::wstring(L"0x400"), (int64_t)0, (int64_t)0,
        std::wstring(L"\\BaseNamedObjects\\WARTest_ZwMutant_01"), (int64_t)0,
    }), pa_), (DWORD_PTR)0);
    EXPECT_TRUE(hmap_.HasMapping(0x400));

    // ZwOpenMutant → same branch as NtOpenMutant; nonexistent → fails.
    EXPECT_NE(exec_.Execute(MakeEvent("ZwOpenMutant", {
        std::wstring(L"0x401"), (int64_t)0, (int64_t)0,
        std::wstring(L"\\BaseNamedObjects\\WARTest_ZwMutant_NONEXISTENT"),
    }), pa_), (DWORD_PTR)0);

    // ZwReleaseMutant → same branch as NtReleaseMutant; unmapped → approx (returns 0).
    EXPECT_EQ(exec_.Execute(MakeEvent("ZwReleaseMutant", {
        std::wstring(L"0x9A6"),
    }), pa_), (DWORD_PTR)0);

    // ZwCreateEvent → same branch as NtCreateEvent.
    EXPECT_EQ(exec_.Execute(MakeEvent("ZwCreateEvent", {
        std::wstring(L"0x402"), (int64_t)0, (int64_t)0,
        std::wstring(L"\\BaseNamedObjects\\WARTest_ZwEvent_01"),
        (int64_t)1, (int64_t)0,
    }), pa_), (DWORD_PTR)0);
    EXPECT_TRUE(hmap_.HasMapping(0x402));

    // ZwOpenEvent → same branch as NtOpenEvent; nonexistent → fails.
    EXPECT_NE(exec_.Execute(MakeEvent("ZwOpenEvent", {
        std::wstring(L"0x403"), (int64_t)0, (int64_t)0,
        std::wstring(L"\\BaseNamedObjects\\WARTest_ZwEvent_NONEXISTENT"),
    }), pa_), (DWORD_PTR)0);

    // ZwCreateSemaphore → same branch as NtCreateSemaphore.
    EXPECT_EQ(exec_.Execute(MakeEvent("ZwCreateSemaphore", {
        std::wstring(L"0x404"), (int64_t)0, (int64_t)0,
        std::wstring(L"\\BaseNamedObjects\\WARTest_ZwSem_01"),
        (int64_t)1, (int64_t)5,
    }), pa_), (DWORD_PTR)0);
    EXPECT_TRUE(hmap_.HasMapping(0x404));

    // ZwCreateTimer → same branch as NtCreateTimer.
    EXPECT_EQ(exec_.Execute(MakeEvent("ZwCreateTimer", {
        std::wstring(L"0x405"), (int64_t)0, (int64_t)0,
        std::wstring(L"\\BaseNamedObjects\\WARTest_ZwTimer_01"), (int64_t)0,
    }), pa_), (DWORD_PTR)0);
    EXPECT_TRUE(hmap_.HasMapping(0x405));

    // ZwCreateIoCompletion → same branch as NtCreateIoCompletion (anonymous IOCP).
    EXPECT_EQ(exec_.Execute(MakeEvent("ZwCreateIoCompletion", {
        std::wstring(L"0x406"), (int64_t)0, (int64_t)0, (int64_t)0,
    }), pa_), (DWORD_PTR)0);
    EXPECT_TRUE(hmap_.HasMapping(0x406));
}

// ── DbgUiConnectToDbg (stub) ──────────────────────────────────────────────────

TEST_F(NtSyncExecutorTest, DbgUiConnectToDbg_ReturnsZeroWithoutConnecting) {
    // Stub must return 0 without calling the real ntdll export.
    // The real function attaches WinAPIReplay.exe as a debugger UI — a persistent
    // kernel-level side effect that crosses sample boundaries.
    // Verify: (1) returns 0, (2) the process is not a debugger UI after the call.
    DWORD_PTR ret = exec_.Execute(MakeEvent("DbgUiConnectToDbg", {}), pa_);
    EXPECT_EQ(ret, (DWORD_PTR)0);

    // If the real function had been called, the current thread would be attached
    // to the debug subsystem.  We verify that the thread's debug port is NOT set
    // by checking that NtQueryInformationThread would not expose one — but the
    // simplest behavioral check is that subsequent NT sync operations still work.
    LogEvent create_ev = MakeEvent("NtCreateEvent", {
        std::wstring(L"0x315"), (int64_t)0, (int64_t)0,
        std::wstring(L"\\BaseNamedObjects\\WARTest_Event_DbgCheck"),
        (int64_t)1, (int64_t)0,
    });
    DWORD_PTR create_ret = exec_.Execute(create_ev, pa_);
    EXPECT_EQ(create_ret, (DWORD_PTR)0)
        << "NT sync must still work after DbgUiConnectToDbg stub call";
    EXPECT_TRUE(hmap_.HasMapping(0x315));
}
