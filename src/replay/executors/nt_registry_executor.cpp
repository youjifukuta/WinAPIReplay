#include "replay/executors/nt_registry_executor.h"
#include "replay/nt_native.h"
#include "replay/utils.h"
#include <windows.h>

// WinMET argument layout for NT registry APIs:
//   NtOpenKey / NtCreateKey   : [0]=out_handle [1]=parent_handle [3]=NT_path [4]=Win32_path
//   NtQueryValueKey            : [0]=handle [1]=value_name
//   NtSetValueKey              : [0]=handle [1]=value_name [3]=type [4]=data
//   NtDeleteValueKey           : [0]=handle [1]=value_name
//   NtDeleteKey / NtFlushKey   : [0]=handle
//   NtQueryKey                 : [0]=handle [1]=info_class
//   NtEnumerateKey             : [0]=handle [1]=index
//   NtEnumerateValueKey        : [0]=handle [1]=index

// ── Helpers ───────────────────────────────────────────────────────────────────

DWORD_PTR NtRegistryExecutor::ReadHexArg(const LogEvent& event, int idx) {
    if (idx >= (int)event.args.size()) return 0;
    if (auto* ws = std::get_if<std::wstring>(&event.args[idx])) {
        try { return HexToPtr(WideToUtf8(*ws)); } catch (...) { return 0; }
    }
    if (auto* iv = std::get_if<std::int64_t>(&event.args[idx]))
        return (DWORD_PTR)*iv;
    return 0;
}

std::wstring NtRegistryExecutor::ReadStrArg(const LogEvent& event, int idx) {
    if (idx >= (int)event.args.size()) return {};
    if (auto* ws = std::get_if<std::wstring>(&event.args[idx])) return *ws;
    return {};
}

HANDLE NtRegistryExecutor::ResolveHKEY(const LogEvent& event, int idx) {
    DWORD_PTR orig = ReadHexArg(event, idx);
    return (HANDLE)handle_map_.Resolve(orig);
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
    return { nullptr, {} };
}

static std::pair<HKEY, std::wstring> ParseNtRegPath(const std::wstring& nt) {
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
}

std::pair<HKEY, std::wstring> NtRegistryExecutor::ParseRegPath(const LogEvent& event) {
    // args[4] = Win32 path "HKEY_LOCAL_MACHINE\..."
    if (event.args.size() > 4) {
        auto ws = ReadStrArg(event, 4);
        if (!ws.empty()) {
            auto [rk, sk] = ParseWin32RegPath(ws);
            if (rk) return { rk, sk };
        }
    }
    // args[3] = NT path "\REGISTRY\MACHINE\..."
    if (event.args.size() > 3) {
        auto ws = ReadStrArg(event, 3);
        if (!ws.empty() && ws[0] == L'\\') {
            auto [rk, sk] = ParseNtRegPath(ws);
            if (rk) return { rk, sk };
        }
    }
    return { nullptr, {} };
}

bool NtRegistryExecutor::BuildSandboxOA(HKEY root_key, const std::wstring& subkey,
                                         std::wstring& rel_path_out,
                                         UNICODE_STRING& us_out,
                                         OBJECT_ATTRIBUTES& oa_out) const {
    if (!hSandboxRoot_) return false;
    // Redirect always returns (HKCU, "Software\WinAPIReplaySandbox\<ROOT>\<subkey>").
    // Strip the "Software\WinAPIReplaySandbox\" prefix to get the path relative to
    // hSandboxRoot_ (which already points to HKCU\Software\WinAPIReplaySandbox).
    auto [sb_hkcu, sb_sub] = reg_sandbox_.Redirect(root_key, subkey);
    size_t prefix_len = wcslen(RegistrySandbox::kSandboxRoot);  // "Software\WinAPIReplaySandbox" = 26
    if (sb_sub.size() > prefix_len + 1)
        rel_path_out = sb_sub.substr(prefix_len + 1);   // "HKLM\Software\Microsoft\..."
    else
        rel_path_out = L"";  // opening sandbox root itself

    NtInitUnicodeString(us_out, rel_path_out);
    InitializeObjectAttributes(&oa_out, &us_out, OBJ_CASE_INSENSITIVE,
                               (HANDLE)hSandboxRoot_, nullptr);
    return true;
}

// ── Initialize (pre-event-loop) ───────────────────────────────────────────────

void NtRegistryExecutor::Initialize() {
    if (!reg_sandbox_.IsEnabled()) return;
    // Pre-create and open the sandbox root via Win32 (init phase, not event replay).
    RegCreateKeyExW(HKEY_CURRENT_USER, RegistrySandbox::kSandboxRoot,
                    0, nullptr, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS,
                    nullptr, &hSandboxRoot_, nullptr);
}

// ── SupportedApis ─────────────────────────────────────────────────────────────

std::vector<std::string> NtRegistryExecutor::SupportedApis() const {
    return {
        "NtOpenKey",          "ZwOpenKey",
        "NtOpenKeyEx",        "ZwOpenKeyEx",
        "NtCreateKey",        "ZwCreateKey",
        "NtQueryValueKey",    "ZwQueryValueKey",
        "NtSetValueKey",      "ZwSetValueKey",
        "NtDeleteValueKey",   "ZwDeleteValueKey",
        "NtQueryKey",         "ZwQueryKey",
        "NtEnumerateKey",     "ZwEnumerateKey",
        "NtEnumerateValueKey","ZwEnumerateValueKey",
        "NtDeleteKey",        "ZwDeleteKey",
        "NtFlushKey",         "ZwFlushKey",
        "NtQueryLicenseValue",
    };
}

// ── Execute ───────────────────────────────────────────────────────────────────

DWORD_PTR NtRegistryExecutor::Execute(const LogEvent& event, const PreparedArgs&) {
    const auto& n   = event.api_name;
    const NtApi& nt = GetNtApi();

    // ── NtOpenKey / NtOpenKeyEx / NtCreateKey ─────────────────────────────────
    if (n == "NtOpenKey"   || n == "ZwOpenKey"   ||
        n == "NtOpenKeyEx" || n == "ZwOpenKeyEx" ||
        n == "NtCreateKey" || n == "ZwCreateKey") {

        DWORD_PTR orig_h = ReadHexArg(event, 0);
        if (orig_h != 0 && handle_map_.HasMapping(orig_h)) return 0;

        HANDLE hkey = nullptr;
        NTSTATUS status = 0xC0000001;  // STATUS_UNSUCCESSFUL

        // Primary path: absolute registry path from log → sandbox via hSandboxRoot_
        auto [root_key, subkey] = ParseRegPath(event);
        if (root_key && reg_sandbox_.IsEnabled()) {
            std::wstring rel;
            UNICODE_STRING us = {};
            OBJECT_ATTRIBUTES oa = {};
            if (BuildSandboxOA(root_key, subkey, rel, us, oa)) {
                if (n == "NtCreateKey" || n == "ZwCreateKey") {
                    if (nt.NtCreateKey) {
                        ULONG disp = 0;
                        status = nt.NtCreateKey(&hkey, KEY_ALL_ACCESS, &oa, 0,
                                                nullptr, REG_OPTION_NON_VOLATILE, &disp);
                    }
                } else if ((n == "NtOpenKeyEx" || n == "ZwOpenKeyEx") && nt.NtOpenKeyEx) {
                    status = nt.NtOpenKeyEx(&hkey, KEY_ALL_ACCESS, &oa, 0);
                } else {
                    // NtOpenKey / ZwOpenKey: open only — fails if key does not exist.
                    if (nt.NtOpenKey)
                        status = nt.NtOpenKey(&hkey, KEY_ALL_ACCESS, &oa);
                }
            }
        }

        // Secondary path: parent handle in HandleMap → open/create relative child key
        if ((!NT_SUCCESS(status) || !hkey)) {
            DWORD_PTR orig_parent = ReadHexArg(event, 1);
            DWORD_PTR real_parent = orig_parent ? handle_map_.Resolve(orig_parent) : 0;
            if (real_parent && real_parent != orig_parent) {
                std::wstring rel = ReadStrArg(event, 3);
                if (rel.empty()) rel = ReadStrArg(event, 4);
                if (!rel.empty() && rel[0] == L'\\') rel = rel.substr(1);
                if (!rel.empty()) {
                    UNICODE_STRING us2 = {};
                    NtInitUnicodeString(us2, rel);
                    OBJECT_ATTRIBUTES oa2 = {};
                    InitializeObjectAttributes(&oa2, &us2, OBJ_CASE_INSENSITIVE,
                                               (HANDLE)real_parent, nullptr);
                    hkey = nullptr;
                    if (n == "NtCreateKey" || n == "ZwCreateKey") {
                        if (nt.NtCreateKey) {
                            ULONG disp2 = 0;
                            status = nt.NtCreateKey(&hkey, KEY_ALL_ACCESS, &oa2, 0,
                                                    nullptr, REG_OPTION_NON_VOLATILE, &disp2);
                        }
                    } else if ((n == "NtOpenKeyEx" || n == "ZwOpenKeyEx") && nt.NtOpenKeyEx) {
                        status = nt.NtOpenKeyEx(&hkey, KEY_ALL_ACCESS, &oa2, 0);
                    } else {
                        if (nt.NtOpenKey)
                            status = nt.NtOpenKey(&hkey, KEY_ALL_ACCESS, &oa2);
                    }
                }
            }
        }

        if (hkey && orig_h) handle_map_.Register(orig_h, (DWORD_PTR)hkey);
        return (DWORD_PTR)status;
    }

    // ── NtQueryValueKey ───────────────────────────────────────────────────────
    if (n == "NtQueryValueKey" || n == "ZwQueryValueKey") {
        if (!nt.NtQueryValueKey) return 0;
        HANDLE hkey = ResolveHKEY(event, 0);
        if (!hkey) return 0;  // approx success for unmapped handle

        std::wstring value_name = ReadStrArg(event, 1);
        UNICODE_STRING us_name = {};
        NtInitUnicodeString(us_name, value_name);

        // Pre-allocated 64 KB buffer; single call only (no size-query step).
        BYTE buf[65536] = {};
        ULONG result_len = 0;
        NTSTATUS status = nt.NtQueryValueKey(hkey, &us_name,
                                              2 /*KeyValuePartialInformation*/,
                                              buf, sizeof(buf), &result_len);
        return (DWORD_PTR)status;
    }

    // ── NtSetValueKey ─────────────────────────────────────────────────────────
    if (n == "NtSetValueKey" || n == "ZwSetValueKey") {
        if (!nt.NtSetValueKey) return 0;
        HANDLE hkey = ResolveHKEY(event, 0);
        if (!hkey) return 0;

        std::wstring value_name = ReadStrArg(event, 1);
        UNICODE_STRING us_name = {};
        NtInitUnicodeString(us_name, value_name);

        ULONG type = (ULONG)ReadHexArg(event, 3);
        std::wstring data_ws = ReadStrArg(event, 4);
        ULONG data_size = (ULONG)(data_ws.size() * sizeof(wchar_t));

        NTSTATUS status = nt.NtSetValueKey(hkey, &us_name, 0, type,
                                            data_ws.empty() ? nullptr
                                                            : (PVOID)data_ws.c_str(),
                                            data_size);
        return (DWORD_PTR)status;
    }

    // ── NtDeleteValueKey ──────────────────────────────────────────────────────
    if (n == "NtDeleteValueKey" || n == "ZwDeleteValueKey") {
        if (!nt.NtDeleteValueKey) return 0;
        HANDLE hkey = ResolveHKEY(event, 0);
        if (!hkey) return 0;
        std::wstring value_name = ReadStrArg(event, 1);
        UNICODE_STRING us_name = {};
        NtInitUnicodeString(us_name, value_name);
        return (DWORD_PTR)nt.NtDeleteValueKey(hkey, &us_name);
    }

    // ── NtQueryKey ────────────────────────────────────────────────────────────
    if (n == "NtQueryKey" || n == "ZwQueryKey") {
        if (!nt.NtQueryKey) return 0;
        HANDLE hkey = ResolveHKEY(event, 0);
        if (!hkey) return 0;
        ULONG info_class = (ULONG)ReadHexArg(event, 1);
        if (!info_class) info_class = 2;  // KeyFullInformation
        BYTE buf[1024] = {};
        ULONG result_len = 0;
        NTSTATUS status = nt.NtQueryKey(hkey, info_class, buf, sizeof(buf), &result_len);
        return (DWORD_PTR)status;
    }

    // ── NtEnumerateKey ────────────────────────────────────────────────────────
    if (n == "NtEnumerateKey" || n == "ZwEnumerateKey") {
        if (!nt.NtEnumerateKey) return (DWORD_PTR)0x8000001A;
        HANDLE hkey = ResolveHKEY(event, 0);
        if (!hkey) return (DWORD_PTR)0x8000001A;
        ULONG index = (ULONG)ReadHexArg(event, 1);
        BYTE buf[1024] = {};
        ULONG result_len = 0;
        NTSTATUS status = nt.NtEnumerateKey(hkey, index, 0 /*KeyBasicInformation*/,
                                             buf, sizeof(buf), &result_len);
        return (DWORD_PTR)status;
    }

    // ── NtEnumerateValueKey ───────────────────────────────────────────────────
    if (n == "NtEnumerateValueKey" || n == "ZwEnumerateValueKey") {
        if (!nt.NtEnumerateValueKey) return (DWORD_PTR)0x8000001A;
        HANDLE hkey = ResolveHKEY(event, 0);
        if (!hkey) return (DWORD_PTR)0x8000001A;
        ULONG index = (ULONG)ReadHexArg(event, 1);
        BYTE buf[1024] = {};
        ULONG result_len = 0;
        NTSTATUS status = nt.NtEnumerateValueKey(hkey, index,
                                                  2 /*KeyValuePartialInformation*/,
                                                  buf, sizeof(buf), &result_len);
        return (DWORD_PTR)status;
    }

    // ── NtDeleteKey ───────────────────────────────────────────────────────────
    if (n == "NtDeleteKey" || n == "ZwDeleteKey") {
        if (!nt.NtDeleteKey) return 0;
        HANDLE hkey = ResolveHKEY(event, 0);
        if (!hkey) return 0;
        return (DWORD_PTR)nt.NtDeleteKey(hkey);
    }

    // ── NtFlushKey ────────────────────────────────────────────────────────────
    if (n == "NtFlushKey" || n == "ZwFlushKey") {
        if (!nt.NtFlushKey) return 0;
        HANDLE hkey = ResolveHKEY(event, 0);
        if (!hkey) return 0;
        return (DWORD_PTR)nt.NtFlushKey(hkey);
    }

    // ── NtQueryLicenseValue ───────────────────────────────────────────────────
    if (n == "NtQueryLicenseValue") {
        // Windows license data unavailable in sandbox environment.
        return (DWORD_PTR)0xC0000034;  // STATUS_OBJECT_NAME_NOT_FOUND
    }

    return 0;
}
