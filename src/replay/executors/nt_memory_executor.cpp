#include "replay/executors/nt_memory_executor.h"
#include "replay/nt_native.h"
#include "replay/utils.h"
#include <windows.h>

// WinMET argument layout for NT memory APIs:
//   NtAllocateVirtualMemory  : [0]=ProcessHandle [1]=BaseAddress [2]=ZeroBits [3]=RegionSize [4]=AllocType [5]=Protect
//   NtFreeVirtualMemory      : [0]=ProcessHandle [1]=BaseAddress [2]=RegionSize [3]=FreeType
//   NtProtectVirtualMemory   : [0]=ProcessHandle [1]=BaseAddress [2]=NumberOfBytesToProtect [3]=NewProtect [4]=OldProtect
//   NtRead/WriteVirtualMemory: [0]=ProcessHandle [1]=BaseAddress [2]=Buffer [3]=ByteCount [4]=BytesTransferred
//   NtCreateSection          : [0]=SectionHandle [1]=DesiredAccess [2]=OA [3]=MaximumSize [4]=SectionPageProtection [5]=AllocationAttributes [6]=FileHandle
//   NtOpenSection            : [0]=SectionHandle [1]=DesiredAccess [2]=OA_name
//   NtMapViewOfSection       : [0]=SectionHandle [1]=ProcessHandle [2]=BaseAddress [3]=ZeroBits [4]=CommitSize [5]=SectionOffset [6]=ViewSize [7]=InheritDisposition [8]=AllocType [9]=Protect
//   NtUnmapViewOfSection     : [0]=ProcessHandle [1]=BaseAddress
//   NtDuplicateObject        : [0]=SrcProc [1]=SrcHandle [2]=TgtProc [3]=TgtHandle [4]=Access [5]=Attr [6]=Options

// ── Helpers ───────────────────────────────────────────────────────────────────

DWORD_PTR NtMemoryExecutor::ReadHexArg(const LogEvent& event, int idx) {
    if (idx >= (int)event.args.size()) return 0;
    if (auto* ws = std::get_if<std::wstring>(&event.args[idx])) {
        try { return HexToPtr(WideToUtf8(*ws)); } catch (...) { return 0; }
    }
    if (auto* iv = std::get_if<std::int64_t>(&event.args[idx]))
        return (DWORD_PTR)*iv;
    return 0;
}

SIZE_T NtMemoryExecutor::ReadSizeArg(const LogEvent& event, int idx) {
    return (SIZE_T)ReadHexArg(event, idx);
}

// ── SupportedApis ─────────────────────────────────────────────────────────────

std::vector<std::string> NtMemoryExecutor::SupportedApis() const {
    return {
        "NtAllocateVirtualMemory", "ZwAllocateVirtualMemory",
        "NtFreeVirtualMemory",     "ZwFreeVirtualMemory",
        "NtProtectVirtualMemory",  "ZwProtectVirtualMemory",
        "NtReadVirtualMemory",     "ZwReadVirtualMemory",
        "NtWriteVirtualMemory",    "ZwWriteVirtualMemory",
        "NtMapViewOfSection",      "ZwMapViewOfSection",
        "NtUnmapViewOfSection",    "ZwUnmapViewOfSection",
        "NtUnmapViewOfSectionEx",
        "NtCreateSection",         "ZwCreateSection",
        "NtOpenSection",           "ZwOpenSection",
        "NtDuplicateObject",       "ZwDuplicateObject",
    };
}

// ── Execute ───────────────────────────────────────────────────────────────────

DWORD_PTR NtMemoryExecutor::Execute(const LogEvent& event, const PreparedArgs&) {
    const auto& n   = event.api_name;
    const NtApi& nt = GetNtApi();

    // ── NtAllocateVirtualMemory ────────────────────────────────────────────────
    if (n == "NtAllocateVirtualMemory" || n == "ZwAllocateVirtualMemory") {
        if (!nt.NtAllocateVirtualMemory) return 0;
        DWORD_PTR orig_base = ReadHexArg(event, 1);
        SIZE_T region_size  = ReadSizeArg(event, 3);
        ULONG alloc_type    = (ULONG)ReadSizeArg(event, 4);
        ULONG protect       = (ULONG)ReadSizeArg(event, 5);

        if (region_size == 0) region_size = 4096;
        if (alloc_type == 0)  alloc_type  = MEM_COMMIT | MEM_RESERVE;
        if (protect == 0)     protect     = PAGE_READWRITE;
        // Normalise executable pages (DEP prevention)
        if (protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                       PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
            protect = PAGE_READWRITE;
        if (region_size > 256ULL * 1024 * 1024) region_size = 4096;

        PVOID base = nullptr;
        SIZE_T sz  = region_size;
        NTSTATUS status = nt.NtAllocateVirtualMemory(
            GetCurrentProcess(), &base, 0, &sz, alloc_type, protect);
        if (NT_SUCCESS(status) && base && orig_base)
            pointer_map_.Register(orig_base, (DWORD_PTR)base);
        return (DWORD_PTR)status;
    }

    // ── NtFreeVirtualMemory ────────────────────────────────────────────────────
    if (n == "NtFreeVirtualMemory" || n == "ZwFreeVirtualMemory") {
        if (!nt.NtFreeVirtualMemory) return 0;
        DWORD_PTR orig_base = ReadHexArg(event, 1);
        DWORD_PTR real_base = (orig_base != 0) ? pointer_map_.Resolve(orig_base) : 0;
        if (real_base && real_base != orig_base) {
            PVOID base = (PVOID)real_base;
            SIZE_T sz  = 0;
            nt.NtFreeVirtualMemory(GetCurrentProcess(), &base, &sz, MEM_RELEASE);
            pointer_map_.Invalidate(orig_base);
        }
        return 0;
    }

    // ── NtProtectVirtualMemory ─────────────────────────────────────────────────
    if (n == "NtProtectVirtualMemory" || n == "ZwProtectVirtualMemory") {
        if (!nt.NtProtectVirtualMemory) return 0;
        DWORD_PTR orig_base = ReadHexArg(event, 1);
        SIZE_T region_size  = ReadSizeArg(event, 2);
        ULONG new_protect   = (ULONG)ReadSizeArg(event, 3);
        DWORD_PTR real_base = (orig_base != 0) ? pointer_map_.Resolve(orig_base) : 0;
        if (real_base && real_base != orig_base && region_size > 0) {
            PVOID base  = (PVOID)real_base;
            SIZE_T sz   = region_size;
            ULONG old   = 0;
            NTSTATUS st = nt.NtProtectVirtualMemory(
                GetCurrentProcess(), &base, &sz, new_protect, &old);
            return (DWORD_PTR)st;
        }
        return 0;
    }

    // ── NtReadVirtualMemory / NtWriteVirtualMemory ────────────────────────────
    // Cross-process memory: target process no longer exists; return success approx.
    if (n == "NtReadVirtualMemory"  || n == "ZwReadVirtualMemory"  ||
        n == "NtWriteVirtualMemory" || n == "ZwWriteVirtualMemory")
        return 0;

    // ── NtCreateSection ────────────────────────────────────────────────────────
    if (n == "NtCreateSection" || n == "ZwCreateSection") {
        if (!nt.NtCreateSection) return 0;
        DWORD_PTR orig_h  = ReadHexArg(event, 0);
        if (orig_h && handle_map_.HasMapping(orig_h)) return 0;
        ULONG access      = (ULONG)ReadHexArg(event, 1);
        if (!access) access = SECTION_ALL_ACCESS;
        SIZE_T max_size   = ReadSizeArg(event, 3);
        ULONG protect     = (ULONG)ReadSizeArg(event, 4);
        ULONG attrs       = (ULONG)ReadSizeArg(event, 5);

        if (max_size == 0) max_size = 4096;
        if (max_size > 256ULL * 1024 * 1024) max_size = 4096;
        if (protect == 0)  protect = PAGE_READWRITE;
        if (protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                       PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
            protect = PAGE_READWRITE;
        if (attrs == 0) attrs = SEC_COMMIT;

        LARGE_INTEGER li;
        li.QuadPart = (LONGLONG)max_size;
        HANDLE h = nullptr;
        // FileHandle = nullptr → pagefile-backed section (anonymous)
        NTSTATUS status = nt.NtCreateSection(&h, access, nullptr, &li,
                                              protect, attrs, nullptr);
        if (NT_SUCCESS(status) && h && orig_h)
            handle_map_.Register(orig_h, (DWORD_PTR)h);
        return (DWORD_PTR)status;
    }

    // ── NtOpenSection ──────────────────────────────────────────────────────────
    if (n == "NtOpenSection" || n == "ZwOpenSection") {
        if (!nt.NtOpenSection) return 0;
        DWORD_PTR orig_h  = ReadHexArg(event, 0);
        if (orig_h && handle_map_.HasMapping(orig_h)) return 0;
        ULONG access      = (ULONG)ReadHexArg(event, 1);
        if (!access) access = SECTION_ALL_ACCESS;

        // Section is named; name in args[2] as NT path string
        std::wstring name;
        if (event.args.size() > 2) {
            if (auto* ws = std::get_if<std::wstring>(&event.args[2])) name = *ws;
        }

        UNICODE_STRING us = {};
        OBJECT_ATTRIBUTES oa = {};
        if (!name.empty()) {
            NtInitUnicodeString(us, name);
            InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
        } else {
            InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);
        }

        HANDLE h = nullptr;
        NTSTATUS status = nt.NtOpenSection(&h, access, name.empty() ? nullptr : &oa);
        if (NT_SUCCESS(status) && h && orig_h)
            handle_map_.Register(orig_h, (DWORD_PTR)h);
        return (DWORD_PTR)status;
    }

    // ── NtMapViewOfSection ─────────────────────────────────────────────────────
    if (n == "NtMapViewOfSection" || n == "ZwMapViewOfSection") {
        if (!nt.NtMapViewOfSection) return 0;
        DWORD_PTR orig_sec  = ReadHexArg(event, 0);
        DWORD_PTR real_sec  = (orig_sec != 0) ? handle_map_.Resolve(orig_sec) : 0;
        DWORD_PTR orig_base = ReadHexArg(event, 2);
        SIZE_T view_size    = ReadSizeArg(event, 6);
        ULONG protect       = (ULONG)ReadSizeArg(event, 9);

        if (view_size == 0) view_size = 4096;
        if (view_size > 256ULL * 1024 * 1024) view_size = 4096;
        if (protect == 0) protect = PAGE_READWRITE;
        if (protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                       PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
            protect = PAGE_READWRITE;

        // NtMapViewOfSection requires a real section handle from a previous NtCreateSection event.
        // If the section handle is not in HandleMap (cross-process or not captured), return
        // approx success without making any extra OS calls (single-call-per-event invariant).
        HANDLE section_h = (real_sec && real_sec != orig_sec)
            ? (HANDLE)real_sec : nullptr;
        if (!section_h) return 0;  // approx: unmapped section handle

        NTSTATUS status = 0xC0000001;
        PVOID base = nullptr;
        SIZE_T vsz = view_size;
        if (nt.NtMapViewOfSection) {
            status = nt.NtMapViewOfSection(section_h, GetCurrentProcess(),
                                            &base, 0, 0, nullptr, &vsz,
                                            1 /*ViewShare*/, 0, protect);
        }

        if (NT_SUCCESS(status) && base && orig_base)
            pointer_map_.Register(orig_base, (DWORD_PTR)base);
        return (DWORD_PTR)status;
    }

    // ── NtUnmapViewOfSection / NtUnmapViewOfSectionEx ─────────────────────────
    if (n == "NtUnmapViewOfSection"   || n == "ZwUnmapViewOfSection"   ||
        n == "NtUnmapViewOfSectionEx") {
        if (!nt.NtUnmapViewOfSection) return 0;
        DWORD_PTR orig_base = ReadHexArg(event, 1);
        DWORD_PTR real_base = (orig_base != 0) ? pointer_map_.Resolve(orig_base) : 0;
        if (real_base && real_base != orig_base) {
            NTSTATUS st = nt.NtUnmapViewOfSection(GetCurrentProcess(), (PVOID)real_base);
            pointer_map_.Invalidate(orig_base);
            return (DWORD_PTR)st;
        }
        return 0;
    }

    // ── NtDuplicateObject ──────────────────────────────────────────────────────
    if (n == "NtDuplicateObject" || n == "ZwDuplicateObject") {
        if (!nt.NtDuplicateObject) return 0;
        DWORD_PTR orig_src_proc = ReadHexArg(event, 0);
        DWORD_PTR orig_src_h    = ReadHexArg(event, 1);
        DWORD_PTR orig_tgt_h    = ReadHexArg(event, 3);

        // Resolve process handle: use current process if unmapped (cross-process)
        DWORD_PTR real_src_proc = handle_map_.Resolve(orig_src_proc);
        HANDLE src_proc = (real_src_proc && real_src_proc != orig_src_proc)
            ? (HANDLE)real_src_proc : GetCurrentProcess();

        DWORD_PTR real_src_h = handle_map_.Resolve(orig_src_h);
        if (!real_src_h || real_src_h == orig_src_h) return 0;

        HANDLE new_handle = nullptr;
        NTSTATUS status = nt.NtDuplicateObject(src_proc, (HANDLE)real_src_h,
                                                GetCurrentProcess(), &new_handle,
                                                0, 0, DUPLICATE_SAME_ACCESS);
        if (NT_SUCCESS(status) && new_handle && orig_tgt_h)
            handle_map_.Register(orig_tgt_h, (DWORD_PTR)new_handle);
        return (DWORD_PTR)status;
    }

    return 0;
}
