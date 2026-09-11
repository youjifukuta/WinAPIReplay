#include "replay/executors/registry_executor.h"
#include "replay/utils.h"
#include <iostream>
#include <variant>
#include <stdexcept>

// WinMET records Win32 registry APIs with args in a different order than
// the Windows API signature. For RegCreateKeyEx[AW], samDesired is at args[3]
// (a hex string) and the output HKEY value is at args[4]. For RegSetValueEx[AW],
// dwType is at args[2] (int64) and the data is at args[3] (string).
static DWORD_PTR ParseHexArg(const LogEvent& event, size_t idx, DWORD_PTR def = 0) {
    if (event.args.size() <= idx) return def;
    const auto& a = event.args[idx];
    if (auto* iv = std::get_if<std::int64_t>(&a)) return (DWORD_PTR)*iv;
    if (auto* wv = std::get_if<std::wstring>(&a)) {
        try {
            std::string s(wv->begin(), wv->end());
            return (DWORD_PTR)std::stoull(s, nullptr, 16);
        } catch (...) {}
    }
    return def;
}

std::vector<std::string> RegistryExecutor::SupportedApis() const {
    return {
        "RegOpenKeyExW", "RegOpenKeyExA",
        "RegCreateKeyExW", "RegCreateKeyExA",
        "RegSetValueExW", "RegSetValueExA",
        "RegQueryValueExW", "RegQueryValueExA",
        "RegDeleteValueW",
        "RegCloseKey",
        "RegDeleteKeyW",
    };
}

static HKEY GetOriginalRoot(const LogEvent& event, HandleMap& hmap) {
    if (event.args.empty()) return nullptr;
    DWORD_PTR v = 0;
    const auto& a0 = event.args[0];
    if (std::holds_alternative<std::int64_t>(a0))
        v = (DWORD_PTR)std::get<std::int64_t>(a0);
    else if (std::holds_alternative<std::wstring>(a0))
        v = HexToPtr(std::string(std::get<std::wstring>(a0).begin(),
                                  std::get<std::wstring>(a0).end()));
    return (HKEY)hmap.Resolve(v);
}


DWORD_PTR RegistryExecutor::Execute(const LogEvent& event, const PreparedArgs& p) {
    const auto& n = event.api_name;

    if (n == "RegOpenKeyExW") {
        // ArgPreparer already sandbox-redirected raw[0]/raw[1]; single call only.
        // Sandbox keys are pre-created in ApiExecutor::PreInit so this should succeed.
        return (DWORD_PTR)RegOpenKeyExW(
            (HKEY)p.raw[0], (LPCWSTR)p.raw[1],
            (DWORD)p.raw[2], (REGSAM)p.raw[3], (PHKEY)p.raw[4]);
    }
    if (n == "RegOpenKeyExA") {
        return (DWORD_PTR)RegOpenKeyExA(
            (HKEY)p.raw[0], (LPCSTR)p.raw[1],
            (DWORD)p.raw[2], (REGSAM)p.raw[3], (PHKEY)p.raw[4]);
    }

    if (n == "RegCreateKeyExW") {
        // WinMET format: args[3]=samDesired(hex), args[4]=original output HKEY value
        // ArgPreparer already sandbox-redirected args[0](root) and args[1](subkey).
        HKEY root = (HKEY)p.raw[0];
        if (!root) {
            HKEY orig_root = GetOriginalRoot(event, handle_map_);
            if (!orig_root) orig_root = HKEY_CURRENT_USER;
            std::wstring sub;
            if (event.args.size() > 1 && std::holds_alternative<std::wstring>(event.args[1]))
                sub = std::get<std::wstring>(event.args[1]);
            auto [sb_root, sb_sub] = reg_sandbox_.Redirect(orig_root, sub);
            root = sb_root;
        }
        REGSAM access = (REGSAM)ParseHexArg(event, 3, KEY_ALL_ACCESS);
        if (!access) access = KEY_ALL_ACCESS;
        DWORD_PTR orig_hk = ParseHexArg(event, 4, 0);
        HKEY hkResult = nullptr;
        DWORD disp = 0;
        LSTATUS r = RegCreateKeyExW(root, (LPCWSTR)p.raw[1], 0, nullptr,
                                    REG_OPTION_NON_VOLATILE, access,
                                    nullptr, &hkResult, &disp);
        if (r == ERROR_SUCCESS && orig_hk)
            handle_map_.Register(orig_hk, (DWORD_PTR)hkResult);
        return (DWORD_PTR)r;
    }
    if (n == "RegCreateKeyExA") {
        // WinMET format: args[3]=samDesired(hex string), args[4]=original output HKEY value
        HKEY root = (HKEY)p.raw[0];
        if (!root) {
            HKEY orig_root = GetOriginalRoot(event, handle_map_);
            if (!orig_root) orig_root = HKEY_CURRENT_USER;
            std::wstring sub;
            if (event.args.size() > 1 && std::holds_alternative<std::wstring>(event.args[1]))
                sub = std::get<std::wstring>(event.args[1]);
            auto [sb_root, sb_sub] = reg_sandbox_.Redirect(orig_root, sub);
            root = sb_root;
        }
        REGSAM access = (REGSAM)ParseHexArg(event, 3, KEY_ALL_ACCESS);
        if (!access) access = KEY_ALL_ACCESS;
        DWORD_PTR orig_hk = ParseHexArg(event, 4, 0);
        HKEY hkResult = nullptr;
        DWORD disp = 0;
        LSTATUS r = RegCreateKeyExA(root, (LPCSTR)p.raw[1], 0, nullptr,
                                    REG_OPTION_NON_VOLATILE, access,
                                    nullptr, &hkResult, &disp);
        if (r == ERROR_SUCCESS && orig_hk)
            handle_map_.Register(orig_hk, (DWORD_PTR)hkResult);
        return (DWORD_PTR)r;
    }

    if (n == "RegSetValueExW") {
        HKEY hk = (HKEY)p.raw[0];
        if (!hk) return (DWORD_PTR)ERROR_SUCCESS;
        // WinMET format: args[2]=dwType(int64), args[3]=data(wstring), args[4]=cbData(int64)
        DWORD dwType = REG_SZ;
        if (event.args.size() > 2) {
            if (auto* iv = std::get_if<int64_t>(&event.args[2])) dwType = (DWORD)*iv;
        }
        DWORD cbData = 0;
        if (event.args.size() > 4) {
            if (auto* iv = std::get_if<int64_t>(&event.args[4])) cbData = (DWORD)*iv;
        }
        if (event.args.size() > 3) {
            const auto& a3 = event.args[3];
            if (auto* wv = std::get_if<std::wstring>(&a3)) {
                if (!cbData) cbData = (DWORD)((wv->size() + 1) * sizeof(wchar_t));
                return (DWORD_PTR)RegSetValueExW(hk, (LPCWSTR)p.raw[1], 0, dwType,
                    (const BYTE*)wv->c_str(), cbData);
            }
            if (auto* iv = std::get_if<std::int64_t>(&a3)) {
                DWORD v = (DWORD)*iv;
                if (!cbData) cbData = 4;
                return (DWORD_PTR)RegSetValueExW(hk, (LPCWSTR)p.raw[1], 0, dwType,
                    (const BYTE*)&v, cbData);
            }
        }
        return (DWORD_PTR)RegSetValueExW(hk, (LPCWSTR)p.raw[1], 0, dwType,
                                          (const BYTE*)p.raw[4], cbData);
    }
    if (n == "RegSetValueExA") {
        HKEY hk = (HKEY)p.raw[0];
        if (!hk) return (DWORD_PTR)ERROR_SUCCESS;
        // WinMET format: args[2]=dwType(int64), args[3]=data(string), args[4]=cbData(int64)
        DWORD dwType = REG_SZ;
        if (event.args.size() > 2) {
            if (auto* iv = std::get_if<int64_t>(&event.args[2])) dwType = (DWORD)*iv;
        }
        DWORD cbData = 0;
        if (event.args.size() > 4) {
            if (auto* iv = std::get_if<int64_t>(&event.args[4])) cbData = (DWORD)*iv;
        }
        if (event.args.size() > 3) {
            const auto& a3 = event.args[3];
            if (auto* wv = std::get_if<std::wstring>(&a3)) {
                std::string s(wv->begin(), wv->end());
                if (!cbData) cbData = (DWORD)(s.size() + 1);
                return (DWORD_PTR)RegSetValueExA(hk, (LPCSTR)p.raw[1], 0, dwType,
                    (const BYTE*)s.c_str(), cbData);
            }
            if (auto* iv = std::get_if<std::int64_t>(&a3)) {
                DWORD v = (DWORD)*iv;
                if (!cbData) cbData = 4;
                return (DWORD_PTR)RegSetValueExA(hk, (LPCSTR)p.raw[1], 0, dwType,
                    (const BYTE*)&v, cbData);
            }
        }
        return (DWORD_PTR)RegSetValueExA(hk, (LPCSTR)p.raw[1], 0, dwType,
                                          (const BYTE*)p.raw[4], cbData);
    }

    if (n == "RegQueryValueExW") {
        // Unmapped handle: return success with empty data
        if (!p.raw[0]) return (DWORD_PTR)ERROR_SUCCESS;
        return (DWORD_PTR)RegQueryValueExW(
            (HKEY)p.raw[0], (LPCWSTR)p.raw[1],
            nullptr, (LPDWORD)p.raw[3],
            (LPBYTE)p.raw[4], (LPDWORD)p.raw[5]);
    }
    if (n == "RegQueryValueExA") {
        if (!p.raw[0]) return (DWORD_PTR)ERROR_SUCCESS;
        return (DWORD_PTR)RegQueryValueExA(
            (HKEY)p.raw[0], (LPCSTR)p.raw[1],
            nullptr, (LPDWORD)p.raw[3],
            (LPBYTE)p.raw[4], (LPDWORD)p.raw[5]);
    }

    if (n == "RegDeleteValueW") {
        if (!p.raw[0]) return (DWORD_PTR)ERROR_SUCCESS;
        return (DWORD_PTR)RegDeleteValueW((HKEY)p.raw[0], (LPCWSTR)p.raw[1]);
    }

    if (n == "RegCloseKey") {
        HKEY h = (HKEY)p.raw[0];
        if (!h) return (DWORD_PTR)ERROR_SUCCESS;
        return (DWORD_PTR)RegCloseKey(h);
    }

    if (n == "RegDeleteKeyW") {
        if (!p.raw[0]) return (DWORD_PTR)ERROR_SUCCESS;
        return (DWORD_PTR)RegDeleteKeyW((HKEY)p.raw[0], (LPCWSTR)p.raw[1]);
    }

    return 0;
}
