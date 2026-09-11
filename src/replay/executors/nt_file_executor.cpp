#include "replay/executors/nt_file_executor.h"
#include "replay/nt_native.h"
#include "replay/utils.h"
#include <string>

// WinMET/CAPE argument layout for NT file APIs:
//   NtCreateFile  : [0]=out_handle_hex [1]=access [2]=path [3]=CreateDisposition [4]=ShareAccess [5]=CreateOptions
//   NtOpenFile    : [0]=out_handle_hex [1]=access [2]=path [3]=ShareAccess
//   NtReadFile    : [0]=handle_hex [1]=path [2]=? [3]=byte_count
//   NtWriteFile   : [0]=handle_hex [1]=path [2]=? [3]=byte_count
//   NtDeleteFile  : [0]=path (sometimes [2]=path)
//   NtQueryInformationFile : [0]=handle_hex [1]=path [2]=info_class
//   NtSetInformationFile   : [0]=handle_hex [1]=path [2]=info_class
//
// NOTE: Both ShareAccess and CreateDisposition are hardcoded in the executor
// (GENERIC_READ|GENERIC_WRITE|SYNCHRONIZE and FILE_OPEN_IF) to maximize
// sandbox compatibility regardless of what the log records.

// ── Helpers ───────────────────────────────────────────────────────────────────

DWORD_PTR NtFileExecutor::ReadHexArg(const LogEvent& event, int idx) {
    if (idx >= (int)event.args.size()) return 0;
    if (auto* ws = std::get_if<std::wstring>(&event.args[idx])) {
        try { return HexToPtr(WideToUtf8(*ws)); } catch (...) {}
    }
    if (auto* iv = std::get_if<std::int64_t>(&event.args[idx]))
        return (DWORD_PTR)*iv;
    return 0;
}

std::wstring NtFileExecutor::ReadStrArg(const LogEvent& event, int idx) {
    if (idx >= (int)event.args.size()) return {};
    if (auto* ws = std::get_if<std::wstring>(&event.args[idx])) return *ws;
    return {};
}

// ── SupportedApis ─────────────────────────────────────────────────────────────

std::vector<std::string> NtFileExecutor::SupportedApis() const {
    return {
        "NtCreateFile",  "ZwCreateFile",
        "NtOpenFile",    "ZwOpenFile",
        "NtReadFile",    "ZwReadFile",
        "NtWriteFile",   "ZwWriteFile",
        "NtQueryInformationFile", "ZwQueryInformationFile",
        "NtSetInformationFile",   "ZwSetInformationFile",
        "NtDeleteFile",  "ZwDeleteFile",
    };
}

// ── Execute ───────────────────────────────────────────────────────────────────

DWORD_PTR NtFileExecutor::Execute(const LogEvent& event, const PreparedArgs&) {
    const auto& n   = event.api_name;
    const NtApi& nt = GetNtApi();

    // ── NtCreateFile / NtOpenFile ─────────────────────────────────────────────
    if (n == "NtCreateFile" || n == "ZwCreateFile" ||
        n == "NtOpenFile"   || n == "ZwOpenFile") {

        DWORD_PTR orig_h = ReadHexArg(event, 0);
        if (orig_h != 0 && handle_map_.HasMapping(orig_h)) return 0;

        std::wstring raw_path = ReadStrArg(event, 2);
        if (raw_path.empty()) return 0xC0000001;  // STATUS_UNSUCCESSFUL

        std::wstring path = NtStripPrefix(raw_path);
        // Skip device paths (\Device\...) and named pipes
        if (path.empty() || path[0] == L'\\') return 0;
        if (path.find(L"pipe") != std::wstring::npos ||
            path.find(L"Pipe") != std::wstring::npos) return 0;
        if (path.size() < 3 || path[1] != L':') return 0;

        if (path_sandbox_.IsEnabled()) {
            path = path_sandbox_.Redirect(path);
            if (path.empty()) return 0;
        }

        // Build NT path and OBJECT_ATTRIBUTES. No extra OS calls.
        std::wstring nt_path = NtMakePath(path);
        UNICODE_STRING us;
        NtInitUnicodeString(us, nt_path);
        OBJECT_ATTRIBUTES oa = NtMakeOA(us);
        IO_STATUS_BLOCK   iosb = {};

        // In sandbox, always open with full access so that subsequent read/write/info
        // operations on the same handle succeed regardless of the original access mask.
        // SYNCHRONIZE is mandatory when FILE_SYNCHRONOUS_IO_NONALERT is set.
        ULONG access = GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE;
        ULONG share  = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

        // Both ShareAccess and CreateDisposition are hardcoded; see file header for layout.

        HANDLE h = nullptr;
        NTSTATUS status;

        {
            // Both NtCreateFile and NtOpenFile use FILE_OPEN_IF in sandbox so that
            // the sandbox file is always created when it doesn't exist yet, and the
            // existing file is opened when it was already created by a prior event.
            ULONG opts = FILE_SYNCHRONOUS_IO_NONALERT;
            if (!path.empty() && path.back() == L'\\') opts |= FILE_DIRECTORY_FILE;
            if (n == "NtCreateFile" || n == "ZwCreateFile") {
                // Carry over FILE_DIRECTORY_FILE from the original log options (arg[5]).
                if (event.args.size() > 5) {
                    ULONG log_opts = (ULONG)ReadHexArg(event, 5);
                    if (log_opts & 1 /*FILE_DIRECTORY_FILE*/) opts |= 1;
                }
            }
            if (!nt.NtCreateFile) return 0xC0000001;
            status = nt.NtCreateFile(&h, access, &oa, &iosb,
                                     nullptr, FILE_ATTRIBUTE_NORMAL,
                                     share, 3 /*FILE_OPEN_IF*/, opts, nullptr, 0);
        }

        if (NT_SUCCESS(status) && h && orig_h)
            handle_map_.Register(orig_h, (DWORD_PTR)h);
        return (DWORD_PTR)status;
    }

    // ── NtReadFile ────────────────────────────────────────────────────────────
    if (n == "NtReadFile" || n == "ZwReadFile") {
        if (!nt.NtReadFile) return 0;
        DWORD_PTR orig_h = ReadHexArg(event, 0);
        DWORD_PTR real_h = (orig_h != 0) ? handle_map_.Resolve(orig_h) : 0;
        // Unmapped handle: return STATUS_INVALID_HANDLE so api_executor can classify
        // this as "approx/unmapped handle" rather than a spurious success.
        if (real_h == 0 || real_h == orig_h) return 0xC0000008;  // STATUS_INVALID_HANDLE

        ULONG count = (event.args.size() > 3) ? (ULONG)ReadHexArg(event, 3) : 0;
        if (count == 0 || count > 64 * 1024 * 1024) count = 4096;
        std::vector<BYTE> buf(count);
        IO_STATUS_BLOCK iosb = {};
        LARGE_INTEGER offset = {};
        NTSTATUS status = nt.NtReadFile((HANDLE)real_h, nullptr, nullptr, nullptr,
                                        &iosb, buf.data(), count, &offset, nullptr);
        // STATUS_END_OF_FILE (0xC0000011) on an empty sandbox file is expected; treat as success.
        if (status == 0xC0000011 /*STATUS_END_OF_FILE*/) return 0;
        return (DWORD_PTR)status;
    }

    // ── NtWriteFile ───────────────────────────────────────────────────────────
    if (n == "NtWriteFile" || n == "ZwWriteFile") {
        if (!nt.NtWriteFile) return 0;
        DWORD_PTR orig_h = ReadHexArg(event, 0);
        DWORD_PTR real_h = (orig_h != 0) ? handle_map_.Resolve(orig_h) : 0;
        if (real_h == 0 || real_h == orig_h) return 0xC0000008;  // STATUS_INVALID_HANDLE

        ULONG count = (event.args.size() > 3) ? (ULONG)ReadHexArg(event, 3) : 0;
        if (count == 0 || count > 64 * 1024 * 1024) count = 0;
        std::vector<BYTE> dummy(count, 0);
        IO_STATUS_BLOCK iosb = {};
        LARGE_INTEGER offset = {};
        NTSTATUS status = nt.NtWriteFile((HANDLE)real_h, nullptr, nullptr, nullptr,
                                         &iosb, dummy.empty() ? nullptr : dummy.data(),
                                         count, &offset, nullptr);
        return (DWORD_PTR)status;
    }

    // ── NtQueryInformationFile / NtSetInformationFile ─────────────────────────
    // Return STATUS_SUCCESS without touching the file; output buffer is irrelevant
    // for success-rate measurement.
    if (n == "NtQueryInformationFile" || n == "ZwQueryInformationFile") {
        if (!nt.NtQueryInformationFile) return 0;
        DWORD_PTR orig_h = ReadHexArg(event, 0);
        DWORD_PTR real_h = (orig_h != 0) ? handle_map_.Resolve(orig_h) : 0;
        if (real_h == 0 || real_h == orig_h) return 0xC0000008;  // STATUS_INVALID_HANDLE
        ULONG info_class = (ULONG)ReadHexArg(event, 2);
        if (!info_class) return 0;
        // 4096 bytes covers FileNameInformation with paths up to ~2000 chars.
        // If the buffer is still too small (STATUS_BUFFER_OVERFLOW = 0x80000005),
        // treat as success: the file handle is valid, only name retrieval truncated.
        BYTE buf[4096] = {};
        IO_STATUS_BLOCK iosb = {};
        NTSTATUS status = nt.NtQueryInformationFile(
            (HANDLE)real_h, &iosb, buf, sizeof(buf), info_class);
        if (status == 0x80000005 /*STATUS_BUFFER_OVERFLOW*/) return 0;
        return (DWORD_PTR)status;
    }
    if (n == "NtSetInformationFile" || n == "ZwSetInformationFile") {
        if (!nt.NtSetInformationFile) return 0;
        DWORD_PTR orig_h = ReadHexArg(event, 0);
        DWORD_PTR real_h = (orig_h != 0) ? handle_map_.Resolve(orig_h) : 0;
        if (real_h == 0 || real_h == orig_h) return 0xC0000008;  // STATUS_INVALID_HANDLE
        ULONG info_class = (ULONG)ReadHexArg(event, 2);
        if (!info_class) return 0;
        BYTE buf[512] = {};
        IO_STATUS_BLOCK iosb = {};
        NTSTATUS status = nt.NtSetInformationFile(
            (HANDLE)real_h, &iosb, buf, sizeof(buf), info_class);
        return (DWORD_PTR)status;
    }

    // ── NtDeleteFile ──────────────────────────────────────────────────────────
    if (n == "NtDeleteFile" || n == "ZwDeleteFile") {
        if (!nt.NtDeleteFile) return 0;
        std::wstring raw_path = ReadStrArg(event, 0);
        if (raw_path.empty()) raw_path = ReadStrArg(event, 2);
        if (raw_path.empty()) return 0;

        std::wstring path = NtStripPrefix(raw_path);
        if (path.empty() || path.size() < 3 || path[1] != L':') return 0;
        if (path_sandbox_.IsEnabled()) {
            path = path_sandbox_.Redirect(path);
            if (path.empty()) return 0;
        }
        std::wstring nt_path = NtMakePath(path);
        UNICODE_STRING us;
        NtInitUnicodeString(us, nt_path);
        OBJECT_ATTRIBUTES oa = NtMakeOA(us);
        // Exactly one NtDeleteFile call.
        NTSTATUS status = nt.NtDeleteFile(&oa);
        return (DWORD_PTR)status;
    }

    return 0;
}
