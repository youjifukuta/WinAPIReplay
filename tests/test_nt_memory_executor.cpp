#include <gtest/gtest.h>
#include <windows.h>
#include "replay/nt_native.h"
#include "replay/handle_map.h"
#include "replay/pointer_map.h"
#include "replay/executors/nt_memory_executor.h"
#include "replay/log_types.h"
#include "replay/arg_preparer.h"

static LogEvent MakeEvent(std::string api,
                           std::initializer_list<ArgValue> args) {
    LogEvent ev;
    ev.api_name = std::move(api);
    ev.args.assign(args);
    return ev;
}

class NtMemoryExecutorTest : public ::testing::Test {
protected:
    HandleMap        hmap_;
    PointerMap       pmap_;
    NtMemoryExecutor exec_{hmap_, pmap_};
    PreparedArgs     pa_{};

    static void SetUpTestSuite() { NtApiLoad(GetNtApi()); }
};

// ── NtAllocateVirtualMemory ───────────────────────────────────────────────────

TEST_F(NtMemoryExecutorTest, NtAllocateVirtualMemory_AllocatesAndRegistersPointer) {
    // args: [ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocType, Protect]
    LogEvent ev = MakeEvent("NtAllocateVirtualMemory", {
        (int64_t)0,                    // [0] ProcessHandle (default → current)
        std::wstring(L"0x10000000"),   // [1] BaseAddress (original malware addr)
        (int64_t)0,                    // [2] ZeroBits
        std::wstring(L"0x1000"),       // [3] RegionSize = 4096
        std::wstring(L"0x3000"),       // [4] MEM_COMMIT | MEM_RESERVE
        std::wstring(L"0x04"),         // [5] PAGE_READWRITE
    });
    DWORD_PTR status = exec_.Execute(ev, pa_);
    EXPECT_EQ(status, (DWORD_PTR)0);   // STATUS_SUCCESS
    EXPECT_NE(pmap_.Resolve((DWORD_PTR)0x10000000), (DWORD_PTR)0x10000000);
}

TEST_F(NtMemoryExecutorTest, NtAllocateVirtualMemory_ExecutableProtect_NormalisedToReadWrite) {
    // Executable pages must be normalised to PAGE_READWRITE (DEP prevention).
    LogEvent ev = MakeEvent("NtAllocateVirtualMemory", {
        (int64_t)0, std::wstring(L"0x20000000"), (int64_t)0,
        std::wstring(L"0x1000"),
        std::wstring(L"0x3000"),
        std::wstring(L"0x20"),  // PAGE_EXECUTE_READ → normalised
    });
    DWORD_PTR status = exec_.Execute(ev, pa_);
    EXPECT_EQ(status, (DWORD_PTR)0);
    EXPECT_NE(pmap_.Resolve((DWORD_PTR)0x20000000), (DWORD_PTR)0x20000000);
}

// ── NtFreeVirtualMemory ───────────────────────────────────────────────────────

TEST_F(NtMemoryExecutorTest, NtFreeVirtualMemory_FreesAllocatedMemory) {
    // Allocate first.
    LogEvent alloc_ev = MakeEvent("NtAllocateVirtualMemory", {
        (int64_t)0, std::wstring(L"0x30000000"), (int64_t)0,
        std::wstring(L"0x1000"), std::wstring(L"0x3000"), std::wstring(L"0x04"),
    });
    exec_.Execute(alloc_ev, pa_);
    ASSERT_NE(pmap_.Resolve((DWORD_PTR)0x30000000), (DWORD_PTR)0x30000000);

    // Free it.
    LogEvent ev = MakeEvent("NtFreeVirtualMemory", {
        (int64_t)0,                    // [0] ProcessHandle
        std::wstring(L"0x30000000"),   // [1] BaseAddress
        (int64_t)0,                    // [2] RegionSize
        (int64_t)0x8000,               // [3] MEM_RELEASE
    });
    exec_.Execute(ev, pa_);
    EXPECT_EQ(pmap_.Resolve((DWORD_PTR)0x30000000), (DWORD_PTR)0x30000000);  // mapping invalidated
}

// ── NtProtectVirtualMemory ────────────────────────────────────────────────────

TEST_F(NtMemoryExecutorTest, NtProtectVirtualMemory_WithMappedPointer_Succeeds) {
    // Allocate.
    LogEvent alloc_ev = MakeEvent("NtAllocateVirtualMemory", {
        (int64_t)0, std::wstring(L"0x40000000"), (int64_t)0,
        std::wstring(L"0x1000"), std::wstring(L"0x3000"), std::wstring(L"0x04"),
    });
    exec_.Execute(alloc_ev, pa_);
    ASSERT_NE(pmap_.Resolve((DWORD_PTR)0x40000000), (DWORD_PTR)0x40000000);

    // Change protection.
    LogEvent ev = MakeEvent("NtProtectVirtualMemory", {
        (int64_t)0,                    // [0] ProcessHandle
        std::wstring(L"0x40000000"),   // [1] BaseAddress
        std::wstring(L"0x1000"),       // [2] NumberOfBytes
        std::wstring(L"0x02"),         // [3] PAGE_READONLY
        (int64_t)0,                    // [4] OldProtect out
    });
    DWORD_PTR status = exec_.Execute(ev, pa_);
    EXPECT_EQ(status, (DWORD_PTR)0);
}

// ── NtCreateSection ───────────────────────────────────────────────────────────

TEST_F(NtMemoryExecutorTest, NtCreateSection_CreatesAndRegistersHandle) {
    LogEvent ev = MakeEvent("NtCreateSection", {
        std::wstring(L"0x400"),   // [0] SectionHandle
        (int64_t)0,               // [1] DesiredAccess (default SECTION_ALL_ACCESS)
        (int64_t)0,               // [2] OA (nullptr → unnamed)
        std::wstring(L"0x1000"), // [3] MaximumSize = 4096
        std::wstring(L"0x04"),   // [4] PAGE_READWRITE
        std::wstring(L"0x8000000"), // [5] SEC_COMMIT
        (int64_t)0,               // [6] FileHandle (nullptr → pagefile-backed)
    });
    DWORD_PTR status = exec_.Execute(ev, pa_);
    EXPECT_EQ(status, (DWORD_PTR)0);
    EXPECT_TRUE(hmap_.HasMapping(0x400));
}

// ── NtMapViewOfSection ────────────────────────────────────────────────────────

TEST_F(NtMemoryExecutorTest, NtMapViewOfSection_WithMappedSection_Succeeds) {
    // Create section first.
    LogEvent create_ev = MakeEvent("NtCreateSection", {
        std::wstring(L"0x401"), (int64_t)0, (int64_t)0,
        std::wstring(L"0x1000"), std::wstring(L"0x04"),
        std::wstring(L"0x8000000"), (int64_t)0,
    });
    exec_.Execute(create_ev, pa_);
    ASSERT_TRUE(hmap_.HasMapping(0x401));

    // Map it.
    LogEvent ev = MakeEvent("NtMapViewOfSection", {
        std::wstring(L"0x401"),   // [0] SectionHandle
        (int64_t)0,               // [1] ProcessHandle (default → current)
        std::wstring(L"0x50000000"), // [2] BaseAddress (orig)
        (int64_t)0,               // [3] ZeroBits
        (int64_t)0,               // [4] CommitSize
        (int64_t)0,               // [5] SectionOffset
        std::wstring(L"0x1000"), // [6] ViewSize
        (int64_t)1,               // [7] InheritDisposition (ViewShare)
        (int64_t)0,               // [8] AllocationType
        std::wstring(L"0x04"),   // [9] Protect PAGE_READWRITE
    });
    DWORD_PTR status = exec_.Execute(ev, pa_);
    EXPECT_EQ(status, (DWORD_PTR)0);
    EXPECT_NE(pmap_.Resolve((DWORD_PTR)0x50000000), (DWORD_PTR)0x50000000);
}

TEST_F(NtMemoryExecutorTest, NtMapViewOfSection_WithUnmappedSection_ReturnsApprox) {
    // 0x99F is not in HandleMap → returns 0 (approx) with no extra OS calls.
    LogEvent ev = MakeEvent("NtMapViewOfSection", {
        std::wstring(L"0x99F"),       // [0] unmapped section handle
        (int64_t)0,                   // [1] ProcessHandle
        std::wstring(L"0x60000000"), // [2] BaseAddress
        (int64_t)0, (int64_t)0, (int64_t)0,
        std::wstring(L"0x1000"),     // [6] ViewSize
        (int64_t)1, (int64_t)0,
        std::wstring(L"0x04"),       // [9] Protect
    });
    DWORD_PTR status = exec_.Execute(ev, pa_);
    EXPECT_EQ(status, (DWORD_PTR)0);  // approx success
    EXPECT_EQ(pmap_.Resolve((DWORD_PTR)0x60000000), (DWORD_PTR)0x60000000);
}

// ── NtUnmapViewOfSection ──────────────────────────────────────────────────────

TEST_F(NtMemoryExecutorTest, NtUnmapViewOfSection_WithMappedView_Succeeds) {
    // Create section and map it.
    LogEvent create_ev = MakeEvent("NtCreateSection", {
        std::wstring(L"0x402"), (int64_t)0, (int64_t)0,
        std::wstring(L"0x1000"), std::wstring(L"0x04"),
        std::wstring(L"0x8000000"), (int64_t)0,
    });
    exec_.Execute(create_ev, pa_);
    ASSERT_TRUE(hmap_.HasMapping(0x402));

    LogEvent map_ev = MakeEvent("NtMapViewOfSection", {
        std::wstring(L"0x402"), (int64_t)0,
        std::wstring(L"0x70000000"),
        (int64_t)0, (int64_t)0, (int64_t)0,
        std::wstring(L"0x1000"),
        (int64_t)1, (int64_t)0, std::wstring(L"0x04"),
    });
    exec_.Execute(map_ev, pa_);
    ASSERT_NE(pmap_.Resolve((DWORD_PTR)0x70000000), (DWORD_PTR)0x70000000);

    // Unmap.
    LogEvent ev = MakeEvent("NtUnmapViewOfSection", {
        (int64_t)0,                    // [0] ProcessHandle
        std::wstring(L"0x70000000"),   // [1] BaseAddress
    });
    DWORD_PTR status = exec_.Execute(ev, pa_);
    EXPECT_EQ(status, (DWORD_PTR)0);
    EXPECT_EQ(pmap_.Resolve((DWORD_PTR)0x70000000), (DWORD_PTR)0x70000000);  // mapping invalidated
}

// ── NtReadVirtualMemory / NtWriteVirtualMemory — approx ──────────────────────

TEST_F(NtMemoryExecutorTest, NtReadVirtualMemory_ReturnsApproxWithoutOsCall) {
    // Cross-process memory: target process gone → always returns 0 (approx).
    LogEvent ev = MakeEvent("NtReadVirtualMemory", {
        (int64_t)0, std::wstring(L"0x1234"), (int64_t)0, (int64_t)4096, (int64_t)0,
    });
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);
}

TEST_F(NtMemoryExecutorTest, NtWriteVirtualMemory_ReturnsApproxWithoutOsCall) {
    LogEvent ev = MakeEvent("NtWriteVirtualMemory", {
        (int64_t)0, std::wstring(L"0x1234"), (int64_t)0, (int64_t)4096, (int64_t)0,
    });
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);
}

// ── NtOpenSection ─────────────────────────────────────────────────────────────

TEST_F(NtMemoryExecutorTest, NtOpenSection_NonexistentName_FailsWithoutCrash) {
    // NtOpenSection for a name that doesn't exist returns a non-zero NTSTATUS.
    LogEvent ev = MakeEvent("NtOpenSection", {
        std::wstring(L"0x403"),   // [0] out handle
        (int64_t)0,               // [1] DesiredAccess (default SECTION_ALL_ACCESS)
        std::wstring(L"\\BaseNamedObjects\\WARTest_Section_NONEXISTENT"), // [2] name
    });
    DWORD_PTR status = exec_.Execute(ev, pa_);
    EXPECT_NE(status, (DWORD_PTR)0);  // STATUS_OBJECT_NAME_NOT_FOUND or similar
    EXPECT_FALSE(hmap_.HasMapping(0x403));
}

// ── NtUnmapViewOfSectionEx ───────────────────────────────────────────────────

TEST_F(NtMemoryExecutorTest, NtUnmapViewOfSectionEx_WithUnmappedBase_ReturnsApprox) {
    // Same code path as NtUnmapViewOfSection; unmapped base → returns 0 (approx).
    LogEvent ev = MakeEvent("NtUnmapViewOfSectionEx", {
        (int64_t)0,                    // [0] ProcessHandle
        std::wstring(L"0x99A"),        // [1] BaseAddress (unmapped)
    });
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);
}

// ── NtDuplicateObject ─────────────────────────────────────────────────────────

TEST_F(NtMemoryExecutorTest, NtDuplicateObject_WithUnmappedSourceHandle_ReturnsApprox) {
    // Unmapped source handle → executor returns 0 (approx success; no real handle).
    LogEvent ev = MakeEvent("NtDuplicateObject", {
        std::wstring(L"0x0"),    // [0] SrcProc (null → current)
        std::wstring(L"0x99B"),  // [1] SrcHandle (unmapped)
        std::wstring(L"0x0"),    // [2] TgtProc
        std::wstring(L"0x99C"),  // [3] TgtHandle (out; not registered on failure)
        (int64_t)0, (int64_t)0, (int64_t)0,
    });
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);
    EXPECT_FALSE(hmap_.HasMapping(0x99C));
}

TEST_F(NtMemoryExecutorTest, NtDuplicateObject_WithMappedSourceHandle_DuplicatesHandle) {
    // Create a section to get a mapped handle, then duplicate it.
    LogEvent create_ev = MakeEvent("NtCreateSection", {
        std::wstring(L"0x404"), (int64_t)0, (int64_t)0,
        std::wstring(L"0x1000"), std::wstring(L"0x04"),
        std::wstring(L"0x8000000"), (int64_t)0,
    });
    exec_.Execute(create_ev, pa_);
    ASSERT_TRUE(hmap_.HasMapping(0x404));

    LogEvent ev = MakeEvent("NtDuplicateObject", {
        std::wstring(L"0x0"),    // [0] SrcProc (unmapped → current process)
        std::wstring(L"0x404"), // [1] SrcHandle (mapped to real section handle)
        std::wstring(L"0x0"),    // [2] TgtProc
        std::wstring(L"0x405"), // [3] TgtHandle (out)
        (int64_t)0, (int64_t)0, (int64_t)0,
    });
    EXPECT_EQ(exec_.Execute(ev, pa_), (DWORD_PTR)0);  // STATUS_SUCCESS
    EXPECT_TRUE(hmap_.HasMapping(0x405));
}

// ── Zw* aliases (same code paths as Nt* variants) ─────────────────────────────

TEST_F(NtMemoryExecutorTest, ZwAliases_ProduceSameOutcomesAsNtVariants) {
    // ZwAllocateVirtualMemory → same branch as NtAllocateVirtualMemory.
    EXPECT_EQ(exec_.Execute(MakeEvent("ZwAllocateVirtualMemory", {
        (int64_t)0, std::wstring(L"0xA0000000"), (int64_t)0,
        std::wstring(L"0x1000"), std::wstring(L"0x3000"), std::wstring(L"0x04"),
    }), pa_), (DWORD_PTR)0);
    EXPECT_NE(pmap_.Resolve((DWORD_PTR)0xA0000000), (DWORD_PTR)0xA0000000);

    // ZwFreeVirtualMemory → same branch as NtFreeVirtualMemory.
    exec_.Execute(MakeEvent("ZwFreeVirtualMemory", {
        (int64_t)0, std::wstring(L"0xA0000000"), (int64_t)0, (int64_t)0x8000,
    }), pa_);
    EXPECT_EQ(pmap_.Resolve((DWORD_PTR)0xA0000000), (DWORD_PTR)0xA0000000);

    // ZwProtectVirtualMemory → allocate first, then protect.
    exec_.Execute(MakeEvent("NtAllocateVirtualMemory", {
        (int64_t)0, std::wstring(L"0xB0000000"), (int64_t)0,
        std::wstring(L"0x1000"), std::wstring(L"0x3000"), std::wstring(L"0x04"),
    }), pa_);
    EXPECT_EQ(exec_.Execute(MakeEvent("ZwProtectVirtualMemory", {
        (int64_t)0, std::wstring(L"0xB0000000"),
        std::wstring(L"0x1000"), std::wstring(L"0x02"), (int64_t)0,
    }), pa_), (DWORD_PTR)0);

    // ZwReadVirtualMemory / ZwWriteVirtualMemory → always return 0 (approx).
    EXPECT_EQ(exec_.Execute(MakeEvent("ZwReadVirtualMemory", {
        (int64_t)0, std::wstring(L"0x1234"), (int64_t)0, (int64_t)4096, (int64_t)0,
    }), pa_), (DWORD_PTR)0);
    EXPECT_EQ(exec_.Execute(MakeEvent("ZwWriteVirtualMemory", {
        (int64_t)0, std::wstring(L"0x1234"), (int64_t)0, (int64_t)4096, (int64_t)0,
    }), pa_), (DWORD_PTR)0);

    // ZwCreateSection → same branch as NtCreateSection.
    EXPECT_EQ(exec_.Execute(MakeEvent("ZwCreateSection", {
        std::wstring(L"0x406"), (int64_t)0, (int64_t)0,
        std::wstring(L"0x1000"), std::wstring(L"0x04"),
        std::wstring(L"0x8000000"), (int64_t)0,
    }), pa_), (DWORD_PTR)0);
    EXPECT_TRUE(hmap_.HasMapping(0x406));

    // ZwMapViewOfSection → same branch as NtMapViewOfSection.
    EXPECT_EQ(exec_.Execute(MakeEvent("ZwMapViewOfSection", {
        std::wstring(L"0x406"), (int64_t)0, std::wstring(L"0xD0000000"),
        (int64_t)0, (int64_t)0, (int64_t)0,
        std::wstring(L"0x1000"), (int64_t)1, (int64_t)0, std::wstring(L"0x04"),
    }), pa_), (DWORD_PTR)0);
    EXPECT_NE(pmap_.Resolve((DWORD_PTR)0xD0000000), (DWORD_PTR)0xD0000000);

    // ZwUnmapViewOfSection → same branch as NtUnmapViewOfSection.
    EXPECT_EQ(exec_.Execute(MakeEvent("ZwUnmapViewOfSection", {
        (int64_t)0, std::wstring(L"0xD0000000"),
    }), pa_), (DWORD_PTR)0);

    // ZwOpenSection → same branch as NtOpenSection; nonexistent → fails.
    DWORD_PTR open_sec_st = exec_.Execute(MakeEvent("ZwOpenSection", {
        std::wstring(L"0x407"), (int64_t)0,
        std::wstring(L"\\BaseNamedObjects\\WARTest_ZwSection_NONEXISTENT"),
    }), pa_);
    EXPECT_NE(open_sec_st, (DWORD_PTR)0);

    // ZwDuplicateObject → same branch as NtDuplicateObject; unmapped src → returns 0.
    EXPECT_EQ(exec_.Execute(MakeEvent("ZwDuplicateObject", {
        std::wstring(L"0x0"), std::wstring(L"0x99D"),
        std::wstring(L"0x0"), std::wstring(L"0x99E"),
        (int64_t)0, (int64_t)0, (int64_t)0,
    }), pa_), (DWORD_PTR)0);
}
