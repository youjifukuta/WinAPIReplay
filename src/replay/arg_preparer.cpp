#include "replay/arg_preparer.h"
#include "replay/utils.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <stdexcept>

using json = nlohmann::json;

// ── SignatureDB ───────────────────────────────────────────────────

static ArgSpec ParseArgSpec(const json& v) {
    ArgSpec s;
    if (v.is_string()) {
        s.type = v.get<std::string>();
    } else if (v.is_object()) {
        s.type         = v.value("type", "DIRECT");
        s.size_bytes   = v.value("size_bytes", 0);
        s.size_arg     = v.value("size_arg", -1);
        s.default_size = v.value("default_size", 65536);
    }
    return s;
}

void SignatureDB::Load(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open())
        throw std::runtime_error("Cannot open signatures: " + path);

    json root;
    f >> root;

    for (auto it = root.begin(); it != root.end(); ++it) {
        if (it.key() == "_meta") continue;
        const json& v = it.value();
        ApiSignature sig;
        sig.module      = v.value("module", "");
        sig.category    = v.value("category", "");
        sig.return_type = v.value("return_type", "DIRECT");

        for (auto& a : v.value("args", json::array()))
            sig.args.push_back(ParseArgSpec(a));

        auto& oh = v["out_handle"];
        if (!oh.is_null() && oh.is_object()) {
            OutHandleSpec spec;
            spec.handle_type = oh.value("type", "HANDLE");
            spec.arg_idx     = oh.value("arg_idx", 0);
            spec.key         = oh.value("key", "");
            sig.out_handle   = spec;
        }

        auto& ia = v["invalidates_arg"];
        if (!ia.is_null() && ia.is_number())
            sig.invalidates_arg = ia.get<int>();

        db_[it.key()] = std::move(sig);
    }
}

const ApiSignature* SignatureDB::Find(const std::string& api_name) const {
    auto it = db_.find(api_name);
    return (it != db_.end()) ? &it->second : nullptr;
}

bool SignatureDB::IsLayer1(const std::string& api_name) const {
    return db_.count(api_name) > 0;
}

// ── ArgPreparer ──────────────────────────────────────────────────

// Returns a human-readable name for a well-known HKEY constant; falls back to hex.
static std::string HkeyName(HKEY h) {
    if (h == HKEY_LOCAL_MACHINE) return "HKLM";
    if (h == HKEY_CURRENT_USER)  return "HKCU";
    if (h == HKEY_CLASSES_ROOT)  return "HKCR";
    if (h == HKEY_USERS)         return "HKU";
    return FormatHex((DWORD_PTR)h);
}

PreparedArgs ArgPreparer::Prepare(const LogEvent& event, const ApiSignature& sig) const {
    PreparedArgs result;
    int n = (int)sig.args.size();
    result.args.resize(n);
    result.raw.resize(n, 0);

    // First pass: find SIZE_INOUT → record which DATA_OUT it controls
    std::unordered_map<int, int> size_inout_controls; // data_out_idx → default_size
    int size_inout_idx = -1;
    for (int i = 0; i < n; i++) {
        if (sig.args[i].type == "SIZE_INOUT") {
            size_inout_idx = i;
            size_inout_controls[sig.args[i].size_arg] = sig.args[i].default_size;
        }
    }
    if (size_inout_idx >= 0) {
        result.size_inout = SizeInoutInfo{
            size_inout_idx,
            sig.args[size_inout_idx].size_arg
        };
    }

    // Second pass: process each arg
    for (int i = 0; i < n; i++) {
        const ArgSpec& spec = sig.args[i];
        ArgValue arg_val = (i < (int)event.args.size())
                         ? event.args[i]
                         : ArgValue{std::nullptr_t{}};

        PreparedArg& pa  = result.args[i];
        DWORD_PTR&   raw = result.raw[i];

        const bool is_null = std::holds_alternative<std::nullptr_t>(arg_val);
        const bool is_int  = std::holds_alternative<std::int64_t>(arg_val);
        const bool is_wstr = std::holds_alternative<std::wstring>(arg_val);

        if (spec.type == "HANDLE") {
            if (is_null)     raw = 0;
            else if (is_int) raw = handle_map_.Resolve((DWORD_PTR)std::get<std::int64_t>(arg_val));
            else             raw = 0;
            pa.value = raw;
        }
        else if (spec.type == "PROCESS_ID") {
            if (is_int) raw = (DWORD_PTR)pid_map_.Resolve((DWORD)std::get<std::int64_t>(arg_val));
            else        raw = 0;
            pa.value = raw;
        }
        else if (spec.type == "WSTRING") {
            if (is_null) { raw = pa.value = 0; }
            else if (is_wstr) {
                std::wstring path = std::get<std::wstring>(arg_val);
                if (path_sandbox_.IsEnabled() && sig.category == "file") {
                    std::wstring redir = path_sandbox_.Redirect(path);
                    if (redir != path)
                        result.transforms.push_back({i, WideToUtf8(path), WideToUtf8(redir)});
                    path = redir;
                }
                pa.buffer.resize((path.size() + 1) * sizeof(wchar_t), 0);
                wcscpy_s(reinterpret_cast<wchar_t*>(pa.buffer.data()), path.size() + 1, path.c_str());
                raw = pa.value = reinterpret_cast<DWORD_PTR>(pa.buffer.data());
            } else { raw = pa.value = 0; }
        }
        else if (spec.type == "REGISTRY_SUBKEY" || spec.type == "REGISTRY_SUBKEY_A") {
            if (is_null) { raw = pa.value = 0; }
            else if (is_wstr) {
                std::wstring subkey = std::get<std::wstring>(arg_val);
                if (reg_sandbox_.IsEnabled() && i > 0) {
                    HKEY actual_hkey = reinterpret_cast<HKEY>(result.args[i-1].value);
                    auto [sandbox_hkey, sandbox_subkey] = reg_sandbox_.Redirect(actual_hkey, subkey);
                    result.args[i-1].value = reinterpret_cast<DWORD_PTR>(sandbox_hkey);
                    result.raw[i-1]        = reinterpret_cast<DWORD_PTR>(sandbox_hkey);
                    // Record the combined hive+subkey transformation
                    std::string orig_full = HkeyName(actual_hkey) + "\\" + WideToUtf8(subkey);
                    std::string rw_full   = HkeyName(sandbox_hkey) + "\\" + WideToUtf8(sandbox_subkey);
                    if (rw_full != orig_full)
                        result.transforms.push_back({i, orig_full, rw_full});
                    subkey = sandbox_subkey;
                }
                if (spec.type == "REGISTRY_SUBKEY") {
                    pa.buffer.resize((subkey.size() + 1) * sizeof(wchar_t), 0);
                    wcscpy_s(reinterpret_cast<wchar_t*>(pa.buffer.data()), subkey.size() + 1, subkey.c_str());
                } else {
                    int len = WideCharToMultiByte(CP_ACP, 0, subkey.c_str(), -1, nullptr, 0, nullptr, nullptr);
                    pa.buffer.resize(len > 0 ? len : 1, 0);
                    WideCharToMultiByte(CP_ACP, 0, subkey.c_str(), -1,
                                        reinterpret_cast<char*>(pa.buffer.data()), len, nullptr, nullptr);
                }
                raw = pa.value = reinterpret_cast<DWORD_PTR>(pa.buffer.data());
            } else { raw = pa.value = 0; }
        }
        else if (spec.type == "ASTRING") {
            if (is_null) { raw = pa.value = 0; }
            else if (is_wstr) {
                std::wstring ws = std::get<std::wstring>(arg_val);
                // Apply PathSandbox for file category (e.g. CreateFileA, DeleteFileA)
                if (path_sandbox_.IsEnabled() && sig.category == "file") {
                    std::wstring redir = path_sandbox_.Redirect(ws);
                    if (redir != ws)
                        result.transforms.push_back({i, WideToUtf8(ws), WideToUtf8(redir)});
                    ws = redir;
                }
                int len = WideCharToMultiByte(CP_ACP, 0, ws.c_str(), -1, nullptr, 0, nullptr, nullptr);
                pa.buffer.resize(len > 0 ? len : 1, 0);
                WideCharToMultiByte(CP_ACP, 0, ws.c_str(), -1,
                                    reinterpret_cast<char*>(pa.buffer.data()), len, nullptr, nullptr);
                raw = pa.value = reinterpret_cast<DWORD_PTR>(pa.buffer.data());
            } else { raw = pa.value = 0; }  // int64_t (lpEnvironment 等) → NULL
        }
        else if (spec.type == "DIRECT") {
            raw = pa.value = is_int ? (DWORD_PTR)std::get<std::int64_t>(arg_val) : 0;
        }
        else if (spec.type == "NULL_OR_PTR") {
            raw = pa.value = 0;
        }
        else if (spec.type == "DATA_IN") {
            std::int64_t sz = 0;
            if (spec.size_arg >= 0 && spec.size_arg < (int)event.args.size()) {
                if (auto* v = std::get_if<std::int64_t>(&event.args[spec.size_arg])) sz = *v;
            } else if (spec.size_bytes > 0) {
                sz = spec.size_bytes;
            }
            if (sz <= 0) sz = 0;
            pa.buffer.assign((size_t)sz, 0);
            raw = pa.value = pa.buffer.empty() ? 0 : reinterpret_cast<DWORD_PTR>(pa.buffer.data());
        }
        else if (spec.type == "DATA_OUT") {
            std::int64_t sz = 0;
            if (size_inout_controls.count(i)) {
                sz = size_inout_controls.at(i);
            } else if (spec.size_bytes > 0) {
                sz = spec.size_bytes;
            } else if (spec.size_arg >= 0 && spec.size_arg < (int)event.args.size()) {
                if (auto* v = std::get_if<std::int64_t>(&event.args[spec.size_arg])) sz = *v;
            }
            if (sz <= 0) sz = 65536;
            pa.buffer.assign((size_t)sz, 0);
            raw = pa.value = reinterpret_cast<DWORD_PTR>(pa.buffer.data());
        }
        else if (spec.type == "SIZE_INOUT") {
            pa.buffer.resize(sizeof(DWORD), 0);
            *reinterpret_cast<DWORD*>(pa.buffer.data()) = (DWORD)spec.default_size;
            raw = pa.value = reinterpret_cast<DWORD_PTR>(pa.buffer.data());
        }
        else if (spec.type == "ADDR_PTR") {
            raw = pa.value = 0;  // NetworkExecutor がバイパスして直接解決する
        }
        else if (spec.type == "PTR_OUT") {
            pa.buffer.resize(sizeof(void*), 0);
            raw = pa.value = reinterpret_cast<DWORD_PTR>(pa.buffer.data());
        }
        else if (spec.type == "HANDLE_ARRAY") {
            if (!event.inline_handles.empty()) {
                for (const auto& hs : event.inline_handles) {
                    DWORD_PTR orig = (DWORD_PTR)std::stoull(hs, nullptr, 16);
                    pa.handle_arr.push_back(reinterpret_cast<HANDLE>(handle_map_.Resolve(orig)));
                }
                raw = pa.value = reinterpret_cast<DWORD_PTR>(pa.handle_arr.data());
            } else {
                raw = pa.value = 0;  // inline_handles 欠如 → nullptr → [APPROX]
            }
        }
        else {
            // 未知の型 → DIRECT として扱う
            raw = pa.value = is_int ? (DWORD_PTR)std::get<std::int64_t>(arg_val) : 0;
        }
    }

    return result;
}
