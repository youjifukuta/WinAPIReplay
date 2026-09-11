#include "replay/api_executor.h"
#include "replay/generic_dispatcher.h"
#include "replay/nt_native.h"
#include "replay/utils.h"
#include <winsock2.h>
#include <shlobj.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <set>
#include <unordered_set>

// ── ReplayStats ──────────────────────────────────────────────────

void ReplayStats::Record(const EventResult& r) {
    std::lock_guard<std::mutex> lock(mutex_);
    ++total;
    if      (r.outcome == "success") ++success;
    else if (r.outcome == "failed")  ++failed;
    else if (r.outcome == "skipped") ++skipped;
    else if (r.outcome == "approx")  ++approx;
    results.push_back(r);
}

// ── ApiExecutor ──────────────────────────────────────────────────

ApiExecutor::ApiExecutor(const SignatureDB& sig_db,
                         ArgPreparer&       arg_prep,
                         HandleMap&         handle_map,
                         PointerMap&        pointer_map,
                         PidMap&            pid_map,
                         const Config&      cfg,
                         PathSandbox&       path_sandbox,
                         RegistrySandbox&   reg_sandbox)
    : sig_db_(sig_db)
    , arg_prep_(arg_prep)
    , handle_map_(handle_map)
    , pointer_map_(pointer_map)
    , pid_map_(pid_map)
    , cfg_(cfg)
    , path_sandbox_(path_sandbox)
    , reg_sandbox_(reg_sandbox)
{}

void ApiExecutor::Register(ExecutorBase* executor) {
    for (const auto& name : executor->SupportedApis())
        dispatch_table_[name] = executor;
}

void ApiExecutor::PreInit(const std::vector<LogEvent>& events) {
    // ── 1. Load ntdll function pointers ──────────────────────────────────────
    NtApiLoad(GetNtApi());

    // ── 2. Pre-create sandbox file directories (Win32 calls, init phase) ─────
    // These SHCreateDirectoryExW calls happen BEFORE the event loop, so they are
    // NOT part of any replayed API call and will not appear in Frida captures.
    if (path_sandbox_.IsEnabled()) {
        // APIs whose args contain file paths, and the arg index where the path lives.
        static const struct { const char* api; int idx; } kFilePaths[] = {
            {"NtCreateFile",2}, {"ZwCreateFile",2},
            {"NtOpenFile",  2}, {"ZwOpenFile",  2},
            {"NtWriteFile", 1}, {"ZwWriteFile", 1},
            {"NtReadFile",  1}, {"ZwReadFile",  1},
            {"NtDeleteFile",0}, {"ZwDeleteFile",0},
            {"CreateFileW", 0}, {"CreateFileA", 0},
            {"CopyFileW",   0}, {"CopyFileW",   1},
            {"MoveFileExW", 0}, {"MoveFileExW", 1},
        };

        std::set<std::wstring> dirs;
        for (const auto& event : events) {
            for (const auto& kfp : kFilePaths) {
                if (event.api_name != kfp.api) continue;
                if (kfp.idx >= (int)event.args.size()) continue;
                const auto* ws = std::get_if<std::wstring>(&event.args[kfp.idx]);
                if (!ws || ws->empty()) continue;
                std::wstring path = NtStripPrefix(*ws);
                if (path.size() < 3 || path[1] != L':') continue;
                std::wstring sb = path_sandbox_.Redirect(path);
                if (sb.empty()) continue;
                auto pos = sb.rfind(L'\\');
                if (pos != std::wstring::npos)
                    dirs.insert(sb.substr(0, pos));
            }
        }
        for (const auto& dir : dirs)
            SHCreateDirectoryExW(nullptr, dir.c_str(), nullptr);
    }

    // ── 3. Pre-create sandbox registry keys (Win32 calls, init phase) ────────
    if (reg_sandbox_.IsEnabled()) {
        // Parse every registry-related event and pre-create the sandbox key.
        // Helper lambdas reuse the same path-parsing logic as NtRegistryExecutor.
        static auto ParseWin32Root = [](const std::wstring& full)
                -> std::pair<HKEY, std::wstring> {
            static const struct { const wchar_t* prefix; HKEY hkey; } kRoots[] = {
                { L"HKEY_LOCAL_MACHINE\\", HKEY_LOCAL_MACHINE },
                { L"HKEY_CURRENT_USER\\",  HKEY_CURRENT_USER  },
                { L"HKEY_CLASSES_ROOT\\",  HKEY_CLASSES_ROOT  },
                { L"HKEY_USERS\\",         HKEY_USERS         },
                { L"HKEY_LOCAL_MACHINE",   HKEY_LOCAL_MACHINE },
                { L"HKEY_CURRENT_USER",    HKEY_CURRENT_USER  },
                { L"HKEY_CLASSES_ROOT",    HKEY_CLASSES_ROOT  },
            };
            for (auto& r : kRoots) {
                size_t plen = wcslen(r.prefix);
                if (full.size() >= plen && _wcsnicmp(full.c_str(), r.prefix, plen) == 0) {
                    std::wstring sub = (full.size() > plen) ? full.substr(plen) : L"";
                    if (!sub.empty() && sub.back() == L'\\') sub.pop_back();
                    return { r.hkey, sub };
                }
            }
            return { nullptr, {} };
        };

        static auto ParseNtRoot = [](const std::wstring& nt)
                -> std::pair<HKEY, std::wstring> {
            const std::wstring kMachine = L"\\REGISTRY\\MACHINE\\";
            if (nt.size() >= kMachine.size() &&
                _wcsnicmp(nt.c_str(), kMachine.c_str(), kMachine.size()) == 0)
                return { HKEY_LOCAL_MACHINE, nt.substr(kMachine.size()) };
            const std::wstring kMachine2 = L"\\REGISTRY\\MACHINE";
            if (_wcsnicmp(nt.c_str(), kMachine2.c_str(), kMachine2.size()) == 0)
                return { HKEY_LOCAL_MACHINE, L"" };
            const std::wstring kUser = L"\\REGISTRY\\USER\\";
            if (nt.size() >= kUser.size() &&
                _wcsnicmp(nt.c_str(), kUser.c_str(), kUser.size()) == 0) {
                std::wstring after = nt.substr(kUser.size());
                auto pos = after.find(L'\\');
                if (pos == std::wstring::npos) return { HKEY_CURRENT_USER, L"" };
                return { HKEY_CURRENT_USER, after.substr(pos + 1) };
            }
            return { nullptr, {} };
        };

        auto TryExtract = [&](const LogEvent& event, int a3, int a4)
                -> std::pair<HKEY, std::wstring> {
            if (a4 >= 0 && a4 < (int)event.args.size()) {
                if (auto* ws = std::get_if<std::wstring>(&event.args[a4]))
                    if (!ws->empty()) { auto r = ParseWin32Root(*ws); if (r.first) return r; }
            }
            if (a3 >= 0 && a3 < (int)event.args.size()) {
                if (auto* ws = std::get_if<std::wstring>(&event.args[a3]))
                    if (!ws->empty() && (*ws)[0] == L'\\') { auto r = ParseNtRoot(*ws); if (r.first) return r; }
            }
            return { nullptr, {} };
        };

        // Collect unique (root, subkey) pairs from all registry events
        std::set<std::wstring> pre_keys;
        for (const auto& event : events) {
            const auto& api = event.api_name;
            HKEY root = nullptr; std::wstring subkey;

            if (api == "NtOpenKey"    || api == "ZwOpenKey"    ||
                api == "NtOpenKeyEx"  || api == "ZwOpenKeyEx"  ||
                api == "NtCreateKey"  || api == "ZwCreateKey") {
                auto [rk, sk] = TryExtract(event, 3, 4);
                root = rk; subkey = sk;
            } else if (api == "RegOpenKeyExW" || api == "RegOpenKeyExA" ||
                       api == "RegCreateKeyExW"|| api == "RegCreateKeyExA") {
                // args[0]=root handle (predefined), args[1]=subkey
                DWORD_PTR v = 0;
                if (!event.args.empty()) {
                    if (auto* iv = std::get_if<std::int64_t>(&event.args[0]))
                        v = (DWORD_PTR)*iv;
                    else if (auto* ws = std::get_if<std::wstring>(&event.args[0])) {
                        try { v = (DWORD_PTR)std::stoull(WideToUtf8(*ws), nullptr, 16); } catch (...) {}
                    }
                }
                HKEY h = (HKEY)handle_map_.Resolve(v);
                if ((ULONG_PTR)h == 0x80000001UL) root = HKEY_CURRENT_USER;
                else if ((ULONG_PTR)h == 0x80000002UL) root = HKEY_LOCAL_MACHINE;
                else root = h;
                if (event.args.size() > 1)
                    if (auto* ws = std::get_if<std::wstring>(&event.args[1])) subkey = *ws;
            }

            if (!root) continue;
            auto [sb_root, sb_sub] = reg_sandbox_.Redirect(root, subkey);
            pre_keys.insert(sb_sub);
        }

        // Create all sandbox keys up-front (creates intermediate keys automatically)
        for (const auto& sub : pre_keys) {
            HKEY dummy = nullptr;
            RegCreateKeyExW(HKEY_CURRENT_USER, sub.c_str(), 0, nullptr,
                            REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS,
                            nullptr, &dummy, nullptr);
            if (dummy) RegCloseKey(dummy);
        }
    }

    // ── 4. Build handle-dependency origin index (handle_dep resolver) ─────────
    BuildHandleOriginIndex(events);

    // ── 5. Initialise each registered executor ────────────────────────────────
    std::unordered_set<ExecutorBase*> seen;
    for (auto& [name, ex] : dispatch_table_) {
        if (seen.insert(ex).second)
            ex->Initialize();
    }
}

std::string ApiExecutor::DetermineOutcome(const std::string& rt, DWORD_PTR result) const {
    if (rt == "VOID")   return "success";
    if (rt == "BOOL")   return (result == 0) ? "failed" : "success";
    // NT_SUCCESS: bits 31-30 == 00 (success) or 01 (informational) → signed value >= 0.
    // Truncate to 32 bits first: executors return (DWORD_PTR)(NTSTATUS) which sign-extends
    // error codes to 0xFFFFFFFF_xxxxxxxx on 64-bit.  STATUS_TIMEOUT (0x102) and
    // STATUS_WAIT_n are NT_SUCCESS but non-zero; "result != 0" would mis-classify them.
    if (rt == "STATUS") {
        NTSTATUS s = (NTSTATUS)(DWORD)result;
        return NT_SUCCESS(s) ? "success" : "failed";
    }
    if (rt == "INT")    return (result == (DWORD_PTR)(INT)SOCKET_ERROR) ? "failed" : "success";
    if (rt == "HANDLE" || rt == "SOCKET" || rt == "HMODULE" ||
        rt == "HINTERNET" || rt == "SC_HANDLE")
        return (result == 0 || result == (DWORD_PTR)INVALID_HANDLE_VALUE) ? "failed" : "success";
    if (rt == "HCRYPTPROV" || rt == "HCRYPTHASH")
        return (result == 0) ? "failed" : "success";
    if (rt == "PTR")    return (result == 0) ? "failed" : "success";
    return "success";  // DIRECT / unknown
}

void ApiExecutor::UpdateMaps(const LogEvent&    event,
                              const ApiSignature& sig,
                              const PreparedArgs& prepared,
                              DWORD_PTR           result) {
    // Return value → HandleMap / PointerMap
    const auto& rt = sig.return_type;
    if (rt == "HANDLE" || rt == "SOCKET" || rt == "HMODULE" ||
        rt == "HINTERNET" || rt == "SC_HANDLE" ||
        rt == "HCRYPTPROV" || rt == "HCRYPTHASH") {
        if (result != 0 && result != (DWORD_PTR)INVALID_HANDLE_VALUE) {
            DWORD_PTR orig = (DWORD_PTR)HexToPtr(event.return_val);
            handle_map_.Register(orig, result);
        }
    } else if (rt == "PTR") {
        DWORD_PTR orig = (DWORD_PTR)HexToPtr(event.return_val);
        if (orig != 0) pointer_map_.Register(orig, result);
    }

    // PTR_OUT args → PointerMap
    for (int i = 0; i < (int)sig.args.size(); i++) {
        if (sig.args[i].type == "PTR_OUT" && !prepared.args[i].buffer.empty()) {
            DWORD_PTR actual_ptr = *reinterpret_cast<const DWORD_PTR*>(prepared.args[i].buffer.data());
            if (i < (int)event.args.size()) {
                if (auto* v = std::get_if<std::int64_t>(&event.args[i])) {
                    pointer_map_.Register((DWORD_PTR)*v, actual_ptr);
                }
            }
        }
    }

    // out_handle → HandleMap / PidMap
    if (sig.out_handle) {
        const auto& oh = *sig.out_handle;
        if (oh.handle_type == "PROCESS_INFORMATION") {
            if (!prepared.args[oh.arg_idx].buffer.empty()) {
                auto* pi = reinterpret_cast<const PROCESS_INFORMATION*>(
                    prepared.args[oh.arg_idx].buffer.data());
                // Find original values from event.out_handles
                std::string orig_hp, orig_ht;
                DWORD orig_pid = 0;
                for (auto& h : event.out_handles) {
                    if (h.key == "hProcess"     && std::holds_alternative<std::string>(h.value))
                        orig_hp = std::get<std::string>(h.value);
                    if (h.key == "hThread"      && std::holds_alternative<std::string>(h.value))
                        orig_ht = std::get<std::string>(h.value);
                    if (h.key == "dwProcessId"  && std::holds_alternative<DWORD>(h.value))
                        orig_pid = std::get<DWORD>(h.value);
                }
                if (!orig_hp.empty())
                    handle_map_.Register(HexToPtr(orig_hp), (DWORD_PTR)pi->hProcess);
                if (!orig_ht.empty())
                    handle_map_.Register(HexToPtr(orig_ht), (DWORD_PTR)pi->hThread);
                if (orig_pid != 0)
                    pid_map_.Register(orig_pid, pi->dwProcessId);
            }
        } else {
            // HKEY / HANDLE / HCRYPTPROV / HCRYPTHASH
            if (!prepared.args[oh.arg_idx].buffer.empty()) {
                HANDLE actual = *reinterpret_cast<const HANDLE*>(
                    prepared.args[oh.arg_idx].buffer.data());
                // Find original value in event.out_handles
                for (auto& h : event.out_handles) {
                    if (h.key == oh.key && std::holds_alternative<std::string>(h.value)) {
                        DWORD_PTR orig = HexToPtr(std::get<std::string>(h.value));
                        handle_map_.Register(orig, (DWORD_PTR)actual);
                        break;
                    }
                }
            }
        }
    }

    // invalidates_arg → HandleMap.Invalidate
    if (sig.invalidates_arg) {
        int idx = *sig.invalidates_arg;
        if (idx < (int)prepared.raw.size())
            handle_map_.Invalidate(prepared.raw[idx]);
    }
}

std::string ApiExecutor::FormatArgList(const LogEvent&    event,
                                        const ApiSignature& sig,
                                        const PreparedArgs& prepared) const {
    int limit = cfg_.verbose ? (int)sig.args.size() : std::min(2, (int)sig.args.size());
    std::ostringstream ss;
    ss << "[";
    for (int i = 0; i < limit; i++) {
        if (i > 0) ss << ", ";
        if (i >= (int)sig.args.size()) break;
        const std::string& type = sig.args[i].type;

        if (type == "WSTRING" || type == "REGISTRY_SUBKEY") {
            if (i < (int)event.args.size() && std::holds_alternative<std::wstring>(event.args[i])) {
                std::string u = WideToUtf8(std::get<std::wstring>(event.args[i]));
                if (u.size() > 50) u = u.substr(0, 47) + "...";
                ss << u;
            } else { ss << "null"; }
        } else if (type == "ASTRING") {
            if (i < (int)event.args.size() && std::holds_alternative<std::wstring>(event.args[i])) {
                std::string u = WideToUtf8(std::get<std::wstring>(event.args[i]));
                if (u.size() > 50) u = u.substr(0, 47) + "...";
                ss << u;
            } else { ss << "null"; }
        } else if (type == "HANDLE" || type == "PROCESS_ID") {
            bool resolved = (i < (int)prepared.raw.size() &&
                             i < (int)event.args.size() &&
                             std::holds_alternative<std::int64_t>(event.args[i]) &&
                             prepared.raw[i] != (DWORD_PTR)std::get<std::int64_t>(event.args[i]));
            ss << FormatHex(i < (int)prepared.raw.size() ? prepared.raw[i] : 0);
            if (resolved) ss << "*";
        } else if (type == "DATA_IN" || type == "DATA_OUT") {
            ss << "<" << (i < (int)prepared.args.size() ? prepared.args[i].buffer.size() : 0) << " bytes>";
        } else if (type == "SIZE_INOUT") {
            ss << "<" << (i < (int)prepared.args.size() ? prepared.args[i].buffer.size() : 0) << " bytes buf>";
        } else if (type == "HANDLE_ARRAY") {
            ss << "<" << (i < (int)prepared.args.size() ? prepared.args[i].handle_arr.size() : 0) << " handles>";
        } else {
            ss << FormatHex(i < (int)prepared.raw.size() ? prepared.raw[i] : 0);
        }
    }
    if ((int)sig.args.size() > limit) ss << " ...";
    ss << "]";
    return ss.str();
}

void ApiExecutor::LogResult(const LogEvent&    event,
                             DWORD_PTR          result,
                             const std::string& outcome,
                             const std::string& note,
                             std::vector<SandboxTransform> transforms) {
    EventResult er;
    er.seq           = event.seq;
    er.api_name      = event.api_name;
    er.outcome       = outcome;
    er.actual_return = FormatHex(result);
    er.note          = note;
    er.transforms    = std::move(transforms);

    std::lock_guard<std::mutex> lock(output_mutex_);
    std::cout << "[REPLAY] seq=" << std::left << std::setw(4) << event.seq
              << "  " << std::setw(22) << event.api_name
              << "  ret=" << FormatHex(result)
              << "  status=" << outcome;
    if (!note.empty()) std::cout << "  " << note;
    std::cout << "\n";

    stats_.Record(er);
}

void ApiExecutor::LogSkip(const LogEvent& event, const std::string& reason) {
    EventResult er;
    er.seq    = event.seq;
    er.api_name = event.api_name;
    er.outcome  = "skipped";
    er.note     = reason;

    std::lock_guard<std::mutex> lock(output_mutex_);
    std::cout << "[SKIP]   seq=" << std::left << std::setw(4) << event.seq
              << "  " << std::setw(22) << event.api_name
              << "  " << reason << "\n";

    stats_.Record(er);
}

void ApiExecutor::LogApprox(const LogEvent& event, DWORD_PTR result, const std::string& note,
                             std::vector<SandboxTransform> transforms) {
    EventResult er;
    er.seq           = event.seq;
    er.api_name      = event.api_name;
    er.outcome       = "approx";
    er.actual_return = FormatHex(result);
    er.note          = note;
    er.transforms    = std::move(transforms);

    std::lock_guard<std::mutex> lock(output_mutex_);
    std::cout << "[APPROX] seq=" << std::left << std::setw(4) << event.seq
              << "  " << std::setw(22) << event.api_name
              << "  " << note
              << "  ret=" << FormatHex(result) << "\n";

    stats_.Record(er);
}

// ── TrySynthHandle helpers ────────────────────────────────────────────────

static DWORD_PTR ExtractOrigHandle(const LogEvent& event) {
    if (event.args.empty()) return 0;
    if (auto* ws = std::get_if<std::wstring>(&event.args[0])) {
        try { return HexToPtr(WideToUtf8(*ws)); } catch (...) {}
    } else if (auto* iv = std::get_if<std::int64_t>(&event.args[0])) {
        return (DWORD_PTR)*iv;
    }
    return 0;
}

static void CreateParentDirs(const std::wstring& path) {
    for (size_t i = 3; i < path.size(); ++i) {
        if (path[i] == L'\\') {
            std::wstring dir = path.substr(0, i);
            CreateDirectoryW(dir.c_str(), nullptr);
        }
    }
}

static std::pair<HKEY, std::wstring> ParseWin32RegPath(const std::wstring& full) {
    static const struct { const wchar_t* prefix; HKEY hkey; } kRoots[] = {
        { L"HKEY_LOCAL_MACHINE\\", HKEY_LOCAL_MACHINE },
        { L"HKEY_CURRENT_USER\\",  HKEY_CURRENT_USER  },
        { L"HKEY_CLASSES_ROOT\\",  HKEY_CLASSES_ROOT  },
        { L"HKEY_USERS\\",         HKEY_USERS         },
        { L"HKEY_LOCAL_MACHINE",   HKEY_LOCAL_MACHINE },
        { L"HKEY_CURRENT_USER",    HKEY_CURRENT_USER  },
        { L"HKEY_CLASSES_ROOT",    HKEY_CLASSES_ROOT  },
    };
    for (auto& r : kRoots) {
        size_t plen = wcslen(r.prefix);
        if (full.size() >= plen && _wcsnicmp(full.c_str(), r.prefix, plen) == 0) {
            std::wstring sub = (full.size() > plen) ? full.substr(plen) : L"";
            if (!sub.empty() && sub.back() == L'\\') sub.pop_back();
            return { r.hkey, sub };
        }
    }
    return { nullptr, L"" };
}

static std::pair<HKEY, std::wstring> ParseNtRegPath(const std::wstring& nt) {
    const std::wstring kMachine = L"\\REGISTRY\\MACHINE\\";
    if (nt.size() > kMachine.size() &&
        _wcsnicmp(nt.c_str(), kMachine.c_str(), kMachine.size()) == 0)
        return { HKEY_LOCAL_MACHINE, nt.substr(kMachine.size()) };

    const std::wstring kUser = L"\\REGISTRY\\USER\\";
    if (nt.size() > kUser.size() &&
        _wcsnicmp(nt.c_str(), kUser.c_str(), kUser.size()) == 0) {
        std::wstring after = nt.substr(kUser.size());
        auto pos = after.find(L'\\');
        if (pos == std::wstring::npos) return { HKEY_CURRENT_USER, L"" };
        return { HKEY_CURRENT_USER, after.substr(pos + 1) };
    }
    return { nullptr, L"" };
}

// ── BuildHandleOriginIndex ────────────────────────────────────────────────────

void ApiExecutor::BuildHandleOriginIndex(const std::vector<LogEvent>& events) {
    all_events_ = &events;
    handle_origin_idx_.clear();
    handle_origin_idx_.reserve(events.size());

    // Win32 APIs where the return value IS the handle AND TrySynthHandle can
    // synthesize the handle.  Only include APIs with a matching TrySynthHandle case;
    // all other "return-value = handle" APIs must be EXCLUDED to avoid poisoning the
    // origin index with unsynthesizable handles (which block file/registry synthesis
    // via the "first occurrence wins" emplace rule).
    static const std::unordered_set<std::string> kRetValHandle = {
        "CreateFileW", "CreateFileA",   // synthesizable via path_sandbox_
        "socket", "WSASocketW",         // synthesizable via net_sim
    };
    // Nt* APIs where arg[0] holds the output handle value (WinMET convention).
    // Only include APIs that TrySynthHandle CAN synthesize; unsynthesizable handle
    // types (section, event, mutant, semaphore, timer) are EXCLUDED to prevent
    // origin index poisoning when their handle values are reused by file/registry APIs.
    static const std::unordered_set<std::string> kNtArg0Handle = {
        "NtCreateFile",    "ZwCreateFile",     // synthesizable via path_sandbox_
        "NtOpenFile",      "ZwOpenFile",
        "NtCreateKey",     "ZwCreateKey",      // synthesizable via reg_sandbox_
        "NtOpenKey",       "ZwOpenKey",
        "NtOpenKeyEx",     "ZwOpenKeyEx",
        "NtOpenProcess",   "ZwOpenProcess",    // synthesizable (self-process handle)
    };

    for (size_t i = 0; i < events.size(); i++) {
        const auto& ev = events[i];
        if (ev.status != "success") continue;

        DWORD_PTR orig = 0;

        if (kRetValHandle.count(ev.api_name)) {
            try { orig = HexToPtr(ev.return_val); } catch (...) {}
        } else if (kNtArg0Handle.count(ev.api_name)) {
            if (!ev.args.empty()) {
                if (auto* ws = std::get_if<std::wstring>(&ev.args[0]))
                    try { orig = HexToPtr(WideToUtf8(*ws)); } catch (...) {}
                else if (auto* iv = std::get_if<std::int64_t>(&ev.args[0]))
                    orig = (DWORD_PTR)*iv;
            }
        } else {
            // Apis that write their handle to an out_handles entry
            // (e.g. RegOpenKeyExW, RegCreateKeyExW, NtOpenProcessToken, etc.)
            for (const auto& oh : ev.out_handles) {
                if (std::holds_alternative<std::string>(oh.value)) {
                    try {
                        orig = HexToPtr(std::get<std::string>(oh.value));
                    } catch (...) {}
                    if (orig) break;
                }
            }
        }

        if (orig != 0 && orig != (DWORD_PTR)INVALID_HANDLE_VALUE)
            handle_origin_idx_.emplace(orig, i);  // first (earliest) occurrence wins
    }
}

// ── TrySynthHandleByValue ─────────────────────────────────────────────────────

bool ApiExecutor::TrySynthHandleByValue(DWORD_PTR original) {
    if (original == 0 || handle_map_.IsPredefined(original) ||
        handle_map_.HasMapping(original))
        return false;

    if (!all_events_) return false;
    auto it = handle_origin_idx_.find(original);
    if (it == handle_origin_idx_.end()) return false;

    return TrySynthHandle((*all_events_)[it->second]);
}

// ── TrySynthHandle ────────────────────────────────────────────────────────────

bool ApiExecutor::TrySynthHandle(const LogEvent& event) {
    if (event.status != "success") return false;

    const std::string& api = event.api_name;

    // Determine the original handle value for this event:
    // - Nt* creation APIs: arg[0] holds the output handle (WinMET convention)
    // - Win32 creation APIs: the return value IS the handle
    static const std::unordered_set<std::string> kRetValApis = {
        "CreateFileW", "CreateFileA",
        "CreateFileMappingW", "CreateFileMappingA",
        "CreateMutexW",  "CreateMutexA",
        "CreateEventW",  "CreateEventA",
        "OpenProcess", "OpenThread",
        "socket", "WSASocketW",
        "FindFirstFileExW", "FindFirstFileW",
        "InternetOpenW", "InternetOpenA",
        "InternetConnectW", "InternetConnectA",
    };
    DWORD_PTR orig = 0;
    if (kRetValApis.count(api)) {
        try { orig = HexToPtr(event.return_val); } catch (...) {}
    } else {
        orig = ExtractOrigHandle(event);  // arg[0] for Nt* APIs
    }
    if (orig == 0 || handle_map_.HasMapping(orig)) return false;

    // ── File handles: NtOpenFile / NtCreateFile ───────────────────────────
    bool is_file = (api == "NtOpenFile"  || api == "NtCreateFile" ||
                    api == "ZwOpenFile"  || api == "ZwCreateFile");
    if (is_file && path_sandbox_.IsEnabled()) {
        if (event.args.size() < 3) return false;
        auto* pw = std::get_if<std::wstring>(&event.args[2]);
        if (!pw || pw->empty()) return false;
        std::wstring path = *pw;

        // Strip NT path prefixes
        auto strip = [&](const wchar_t* pfx) {
            size_t n = wcslen(pfx);
            if (path.size() > n && _wcsnicmp(path.c_str(), pfx, n) == 0)
                path = path.substr(n);
        };
        strip(L"\\??\\");
        strip(L"\\?\\");

        // Skip non-filesystem paths (devices, named pipes, etc.)
        if (path.empty() || path[0] == L'\\') return false;
        if (path.find(L"pipe") != std::wstring::npos ||
            path.find(L"Pipe") != std::wstring::npos) return false;

        std::wstring sb = path_sandbox_.Redirect(path);
        CreateParentDirs(sb);

        HANDLE h = CreateFileW(sb.c_str(),
                               GENERIC_READ | GENERIC_WRITE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            // Might be a directory path — retry with backup semantics
            h = CreateFileW(sb.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        }
        if (h != INVALID_HANDLE_VALUE) {
            handle_map_.Register(orig, (DWORD_PTR)h);
            return true;
        }
        return false;
    }

    // ── Registry handles: NtOpenKey / NtCreateKey / NtOpenKeyEx ──────────
    bool is_reg = (api == "NtOpenKey"   || api == "NtCreateKey" ||
                   api == "NtOpenKeyEx" || api == "ZwOpenKey"   ||
                   api == "ZwCreateKey" || api == "ZwOpenKeyEx");
    if (is_reg && reg_sandbox_.IsEnabled()) {
        HKEY         root_key = nullptr;
        std::wstring subkey;

        // Strategy 1: args[4] as Win32 full path "HKEY_xxx\subkey"
        if (event.args.size() > 4) {
            if (auto* ws = std::get_if<std::wstring>(&event.args[4])) {
                auto [rk, sk] = ParseWin32RegPath(*ws);
                if (rk) { root_key = rk; subkey = sk; }
            }
        }
        // Strategy 2: args[3] as NT path "\REGISTRY\..."
        if (!root_key && event.args.size() > 3) {
            if (auto* ws = std::get_if<std::wstring>(&event.args[3])) {
                if (!ws->empty() && (*ws)[0] == L'\\') {
                    auto [rk, sk] = ParseNtRegPath(*ws);
                    if (rk) { root_key = rk; subkey = sk; }
                }
            }
        }
        if (!root_key) return false;

        auto [sb_root, sb_sub] = reg_sandbox_.Redirect(root_key, subkey);
        HKEY hkey = nullptr;
        LONG rc = RegCreateKeyExW(sb_root, sb_sub.c_str(), 0, nullptr,
                                  REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS,
                                  nullptr, &hkey, nullptr);
        if (rc == ERROR_SUCCESS && hkey) {
            handle_map_.Register(orig, (DWORD_PTR)hkey);
            return true;
        }
        return false;
    }

    // ── Process handles: NtOpenProcess ───────────────────────────────────
    if (api == "NtOpenProcess" || api == "ZwOpenProcess") {
        HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
        if (!h) h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
        if (h) {
            handle_map_.Register(orig, (DWORD_PTR)h);
            return true;
        }
        return false;
    }

    // ── Win32 file handles: CreateFileW/A ─────────────────────────────────────
    if ((api == "CreateFileW" || api == "CreateFileA") && path_sandbox_.IsEnabled()) {
        std::wstring path;
        if (!event.args.empty()) {
            if (auto* ws = std::get_if<std::wstring>(&event.args[0])) path = *ws;
        }
        if (path.empty() || path.size() < 3 || path[1] != L':') return false;
        std::wstring sb = path_sandbox_.Redirect(path);
        CreateParentDirs(sb);
        HANDLE h = CreateFileW(sb.c_str(),
                               GENERIC_READ | GENERIC_WRITE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            h = CreateFileW(sb.c_str(), GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, OPEN_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        }
        if (h != INVALID_HANDLE_VALUE) {
            handle_map_.Register(orig, (DWORD_PTR)h);
            return true;
        }
        return false;
    }

    // ── Win32 registry handles: RegOpenKeyExW/A, RegCreateKeyExW/A ───────────
    if ((api == "RegOpenKeyExW"  || api == "RegCreateKeyExW" ||
         api == "RegOpenKeyExA"  || api == "RegCreateKeyExA") &&
        reg_sandbox_.IsEnabled()) {
        HKEY         root = nullptr;
        std::wstring subkey;

        if (!event.args.empty()) {
            DWORD_PTR v = 0;
            if (auto* iv = std::get_if<std::int64_t>(&event.args[0]))
                v = (DWORD_PTR)*iv;
            else if (auto* ws = std::get_if<std::wstring>(&event.args[0]))
                try { v = HexToPtr(WideToUtf8(*ws)); } catch (...) {}
            HKEY rk = (HKEY)handle_map_.Resolve(v);
            ULONG_PTR rv = (ULONG_PTR)rk;
            if      (rv == 0x80000000UL) root = HKEY_CLASSES_ROOT;
            else if (rv == 0x80000001UL) root = HKEY_CURRENT_USER;
            else if (rv == 0x80000002UL) root = HKEY_LOCAL_MACHINE;
            else if (rv == 0x80000003UL) root = HKEY_USERS;
            else                         root = rk;
        }
        if (!root) return false;

        if (event.args.size() > 1) {
            if (auto* ws = std::get_if<std::wstring>(&event.args[1])) subkey = *ws;
        }

        auto [sb_root, sb_sub] = reg_sandbox_.Redirect(root, subkey);
        HKEY hkey = nullptr;
        LONG rc = RegCreateKeyExW(sb_root, sb_sub.c_str(), 0, nullptr,
                                  REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS,
                                  nullptr, &hkey, nullptr);
        if (rc == ERROR_SUCCESS && hkey) {
            handle_map_.Register(orig, (DWORD_PTR)hkey);
            return true;
        }
        return false;
    }

    // ── Win32 socket handles: socket() / WSASocketW() ─────────────────────────
    if (api == "socket" || api == "WSASocketW") {
        WSADATA wd{}; WSAStartup(MAKEWORD(2, 2), &wd);
        int af = AF_INET, type = SOCK_STREAM, proto = IPPROTO_TCP;
        if (event.args.size() > 0) if (auto* iv = std::get_if<std::int64_t>(&event.args[0])) af    = (int)*iv;
        if (event.args.size() > 1) if (auto* iv = std::get_if<std::int64_t>(&event.args[1])) type  = (int)*iv;
        if (event.args.size() > 2) if (auto* iv = std::get_if<std::int64_t>(&event.args[2])) proto = (int)*iv;
        SOCKET s = ::socket(af, type, proto);
        if (s == INVALID_SOCKET) return false;
        handle_map_.Register(orig, (DWORD_PTR)s);
        return true;
    }

    return false;
}

// ── Execute ───────────────────────────────────────────────────────────────

void ApiExecutor::Execute(const LogEvent& event) {
    if (cfg_.dry_run) {
        LogSkip(event, "dry-run");
        return;
    }

    // Skip APIs that would terminate the replay process itself
    static const std::unordered_set<std::string> kDangerousApis = {
        "NtTerminateThread",  "NtTerminateProcess",
        "TerminateThread",    "TerminateProcess",
        "ExitThread",         "ExitProcess",
        "RtlExitUserThread",  "RtlExitUserProcess",
    };
    if (kDangerousApis.count(event.api_name)) {
        LogSkip(event, "dangerous: would terminate replay");
        return;
    }

    // ── kLayer2Blocked: checked BEFORE sig_db_ to enforce strict mutual exclusivity.
    // These are APIs with NO safe Layer-1 executor that would be dangerous if
    // dispatched via GenericDispatcher with garbage args from the WinMET log.
    // INVARIANT: every API listed here must NOT appear in any executor's SupportedApis().
    static const std::unordered_set<std::string> kLayer2Blocked = {
        // Extended multi-object wait: no executor; NtWaitForMultipleObjects is handled
        // by NtSyncExecutor but the *Ex variant adds extra args with no safe default.
        "NtWaitForMultipleObjectsEx",

        // COM object instantiation with CLSID/IID GUIDs: no executor for the Ex form.
        // CoCreateInstance is handled by NtMiscExecutor (stub); CoCreateInstanceEx is not.
        "CoCreateInstanceEx",

        // Legacy process creation variants: no executor.
        // NtCreateUserProcess / ZwCreateUserProcess are handled by NtMiscExecutor (stub).
        "NtCreateProcessEx", "ZwCreateProcessEx",

        // Zw variants of sync objects where only the Nt variant is in NtSyncExecutor.
        "ZwOpenSemaphore",
        "ZwOpenTimer",
    };
    if (kLayer2Blocked.count(event.api_name)) {
        bool synth = TrySynthHandle(event);
        LogSkip(event, synth
            ? "Layer2: blocked (handle synthesized)"
            : "Layer2: blocked (unsafe in replay context)");
        return;
    }

    const ApiSignature* sig = sig_db_.Find(event.api_name);
    if (cfg_.no_l1_executor) sig = nullptr;  // Ablation: force all APIs to Layer2

    if (sig) {
        // Layer 1

        // Handle-dependency pre-synthesis: if any HANDLE-typed arg is unmapped,
        // look it up in the pre-scanned origin index and synthesize the resource
        // before Prepare() resolves it.  This converts handle_dep "approx" events
        // into genuine "success" events for file, registry, and socket handles.
        for (int i = 0; i < (int)sig->args.size(); i++) {
            if (sig->args[i].type != "HANDLE") continue;
            if (i >= (int)event.args.size()) continue;
            DWORD_PTR orig_h = 0;
            if (auto* iv = std::get_if<std::int64_t>(&event.args[i]))
                orig_h = (DWORD_PTR)*iv;
            else if (auto* ws = std::get_if<std::wstring>(&event.args[i]))
                try { orig_h = HexToPtr(WideToUtf8(*ws)); } catch (...) {}
            if (orig_h != 0 && !handle_map_.IsPredefined(orig_h) &&
                !handle_map_.HasMapping(orig_h))
                TrySynthHandleByValue(orig_h);
        }

        PreparedArgs prepared = arg_prep_.Prepare(event, *sig);

        // Extension A: Record NetSim transforms for network connection APIs.
        // The original destination IP/hostname is in event.args; the executor
        // rewrites it to 127.0.0.1.  Record this so sysmon_analyzer can restore
        // the original C2 address in Sysmon Event 3.
        if (cfg_.net_sim) {
            auto arg_str = [&](int idx) -> std::string {
                if (idx < (int)event.args.size()) {
                    if (auto* ws = std::get_if<std::wstring>(&event.args[idx]))
                        return WideToUtf8(*ws);
                }
                return {};
            };
            auto arg_int = [&](int idx) -> int64_t {
                if (idx < (int)event.args.size())
                    if (auto* v = std::get_if<std::int64_t>(&event.args[idx]))
                        return *v;
                return 0;
            };

            // Returns true only for printable ASCII strings (valid IPs / hostnames).
            // connect() stores a sockaddr* in arg[1]; WinMET may not decode the binary
            // sockaddr to a string, so arg_str(1) can be binary garbage.
            auto is_valid_addr = [](const std::string& s) -> bool {
                if (s.empty() || s.size() > 253) return false;
                for (unsigned char c : s)
                    if (c < 32 || c > 126) return false;
                return true;
            };

            const auto& n = event.api_name;
            if (n == "connect" || n == "WSAConnect") {
                // arg[1] = IP string, arg[2] = port integer
                std::string ip   = arg_str(1);
                int64_t     port = arg_int(2);
                if (!ip.empty() && ip != "127.0.0.1" && is_valid_addr(ip)) {
                    std::string orig = ip + ":" + std::to_string(port);
                    prepared.transforms.push_back({1, orig, "127.0.0.1"});
                }
            } else if (n == "GetAddrInfoW") {
                // arg[0] = WSTRING hostname
                std::string host = arg_str(0);
                if (!host.empty() && host != "127.0.0.1")
                    prepared.transforms.push_back({0, host, "127.0.0.1"});
            }
        }

        // HANDLE_ARRAY with missing inline_handles → [APPROX]
        for (int i = 0; i < (int)sig->args.size(); i++) {
            if (sig->args[i].type == "HANDLE_ARRAY" && prepared.raw[i] == 0 &&
                event.inline_handles.empty()) {
                DWORD result = 0;
                auto it = dispatch_table_.find(event.api_name);
                if (it != dispatch_table_.end()) {
                    result = (DWORD)it->second->Execute(event, prepared);
                }
                LogApprox(event, result, "inline_handles missing", prepared.transforms);
                return;
            }
        }

        // Extension B helper: record process creation telemetry (called from here
        // for "no executor" skips and from the bottom of Execute() for executed calls).
        static const std::unordered_set<std::string> kCreateProcessApis = {
            "CreateProcessW", "CreateProcessA"
        };
        auto RecordProcessEvent = [&](const std::string& outcome) {
            if (!kCreateProcessApis.count(event.api_name)) return;
            auto arg_wstr = [&](int idx) -> std::string {
                if (idx < (int)event.args.size())
                    if (auto* ws = std::get_if<std::wstring>(&event.args[idx]))
                        return WideToUtf8(*ws);
                return {};
            };
            ProcessEvent pe;
            pe.seq               = event.seq;
            pe.api_name          = event.api_name;
            pe.application       = arg_wstr(0);
            pe.command_line      = arg_wstr(1);
            pe.current_directory = arg_wstr(7);
            pe.outcome           = outcome;
            std::lock_guard<std::mutex> lk(output_mutex_);
            stats_.process_events.push_back(std::move(pe));
        };

        // Find executor
        auto it = dispatch_table_.find(event.api_name);
        if (it == dispatch_table_.end()) {
            LogSkip(event, "Layer1: no executor registered");
            RecordProcessEvent("skipped");
            return;
        }

        DWORD_PTR result = it->second->Execute(event, prepared);

        UpdateMaps(event, *sig, prepared, result);

        std::string outcome = DetermineOutcome(sig->return_type, result);
        std::string note;

        // If failed, check whether the cause is an unmapped handle (log incomplete).
        // Such handles were created before capture started or by uncaptured calls.
        if (outcome == "failed") {
            // Check 1: unmapped handle (created before capture started)
            for (int i = 0; i < (int)sig->args.size(); i++) {
                if (sig->args[i].type != "HANDLE" || i >= (int)event.args.size()) continue;
                DWORD_PTR orig = 0;
                if (auto* iv = std::get_if<std::int64_t>(&event.args[i]))
                    orig = (DWORD_PTR)*iv;
                else if (auto* sv = std::get_if<std::wstring>(&event.args[i]))
                    try { orig = HexToPtr(WideToUtf8(*sv)); } catch (...) { orig = 0; }
                if (orig != 0 && !handle_map_.IsPredefined(orig) &&
                    !handle_map_.HasMapping(orig)) {
                    outcome = "approx";
                    note    = "unmapped handle";
                    break;
                }
            }
            // Check 2: net-sim socket state mismatch (socket closed/expired in sim)
            static const std::unordered_set<std::string> kSocketOps = {
                "connect", "WSAConnect",
                "recv", "recvfrom", "send", "sendto", "closesocket",
                "WSASend", "WSARecv", "WSASendMsg", "WSARecvMsg",
                "accept", "WSAAccept", "shutdown", "listen"
            };
            if (outcome == "failed" && cfg_.net_sim && kSocketOps.count(event.api_name)) {
                outcome = "approx";
                note    = "net-sim state";
            }
            // Check 3: registry value/key absent on replay VM (environment difference)
            static const std::unordered_set<std::string> kRegQueryOps = {
                "RegQueryValueExW", "RegQueryValueExA",
                "RegOpenKeyExW",    "RegOpenKeyExA",
                "RegDeleteValueW",  "RegDeleteValueA",
                "RegDeleteKeyW",    "RegDeleteKeyExW",  "RegDeleteKeyExA"
            };
            if (outcome == "failed" && cfg_.sandbox_registry && kRegQueryOps.count(event.api_name)) {
                outcome = "approx";
                note    = "registry env diff";
            }
        }

        std::string final_outcome = (sig->return_type == "VOID") ? "success" : outcome;
        if (sig->return_type != "VOID")
            LogResult(event, result, outcome, note, prepared.transforms);
        else
            LogResult(event, 0, "success", "", prepared.transforms);

        RecordProcessEvent(final_outcome);  // Extension B
    } else {
        // Layer 2: no sig_db_ entry → GenericDispatcher (best-effort call via GetProcAddress)
        DWORD_PTR result = 0;
        if (generic_dispatcher_ && generic_dispatcher_->Dispatch(event, result)) {
            LogResult(event, result, "success");
        } else {
            LogSkip(event, "Layer2: no export found");
        }
    }
}
