#include "replay/executors/service_executor.h"
#include <windows.h>
#include <winsvc.h>

std::vector<std::string> ServiceExecutor::SupportedApis() const {
    return {
        "OpenSCManagerW", "OpenSCManagerA",
        "OpenServiceW", "OpenServiceA",
        "CreateServiceW", "CreateServiceA",
        "StartServiceW", "StartServiceA",
        "ControlService",
        "CloseServiceHandle",
    };
}

// Return a valid SC handle for a service that is guaranteed to exist on any Windows VM.
// Used as a stand-in when the original service is not installed on the replay host.
static SC_HANDLE SynthServiceHandle(SC_HANDLE hScm, DWORD dwAccess) {
    static const wchar_t* kFallbacks[] = {
        L"EventLog", L"Schedule", L"PlugPlay", L"RpcSs", nullptr
    };
    for (int i = 0; kFallbacks[i]; ++i) {
        SC_HANDLE h = OpenServiceW(hScm, kFallbacks[i], dwAccess);
        if (h) return h;
        h = OpenServiceW(hScm, kFallbacks[i], SERVICE_QUERY_STATUS);
        if (h) return h;
    }
    return nullptr;
}

DWORD_PTR ServiceExecutor::Execute(const LogEvent& event, const PreparedArgs& p) {
    const auto& n = event.api_name;

    if (n == "OpenSCManagerW") {
        // Use minimum required access; p.raw[2] may be 0 when arg recorded as hex string
        DWORD access = (DWORD)p.raw[2];
        if (access == 0) access = SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE;
        SC_HANDLE h = OpenSCManagerW(nullptr, nullptr, access);
        if (!h) h = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        return (DWORD_PTR)h;
    }
    if (n == "OpenSCManagerA") {
        DWORD access = (DWORD)p.raw[2];
        if (access == 0) access = SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE;
        SC_HANDLE h = OpenSCManagerA(nullptr, nullptr, access);
        if (!h) h = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
        return (DWORD_PTR)h;
    }

    if (n == "OpenServiceW") {
        SC_HANDLE hScm = (SC_HANDLE)p.raw[0];
        DWORD access = (DWORD)p.raw[2];
        if (access == 0) access = SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG;
        SC_HANDLE h = nullptr;
        if (hScm) h = OpenServiceW(hScm, (LPCWSTR)p.raw[1], access);
        // Service not installed on replay host: substitute a known-present service
        if (!h) {
            SC_HANDLE tmp_scm = hScm;
            if (!tmp_scm)
                tmp_scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
            if (tmp_scm) {
                h = SynthServiceHandle(tmp_scm, SERVICE_QUERY_STATUS);
                if (!hScm) CloseServiceHandle(tmp_scm);
            }
        }
        return (DWORD_PTR)h;
    }
    if (n == "OpenServiceA") {
        SC_HANDLE hScm = (SC_HANDLE)p.raw[0];
        DWORD access = (DWORD)p.raw[2];
        if (access == 0) access = SERVICE_QUERY_STATUS;
        SC_HANDLE h = nullptr;
        if (hScm) h = OpenServiceA(hScm, (LPCSTR)p.raw[1], access);
        if (!h) {
            SC_HANDLE tmp_scm = hScm;
            if (!tmp_scm)
                tmp_scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
            if (tmp_scm) {
                h = SynthServiceHandle(tmp_scm, SERVICE_QUERY_STATUS);
                if (!hScm) CloseServiceHandle(tmp_scm);
            }
        }
        return (DWORD_PTR)h;
    }

    if (n == "CreateServiceW" || n == "CreateServiceA") {
        // Stub: do NOT install real services from malware logs.
        // CreateServiceW/A would write to the SCM database (persisted in the registry
        // outside the replay sandbox), polluting the VM's service list across samples.
        // Return a handle to a known-benign existing service so downstream
        // ControlService / CloseServiceHandle calls have a valid handle to operate on.
        SC_HANDLE hScm = (SC_HANDLE)p.raw[0];
        if (!hScm) return (DWORD_PTR)nullptr;
        return (DWORD_PTR)SynthServiceHandle(hScm, SERVICE_QUERY_STATUS);
    }

    if (n == "StartServiceW" || n == "StartServiceA") {
        // Stub: do not start services from malware logs.
        // The underlying service binary doesn't exist on the replay VM,
        // so the call would fail anyway; report success without the attempt.
        return (DWORD_PTR)TRUE;
    }

    if (n == "ControlService") {
        if (!p.raw[0]) return (DWORD_PTR)TRUE;
        SERVICE_STATUS ss{};
        return (DWORD_PTR)ControlService((SC_HANDLE)p.raw[0], (DWORD)p.raw[1], &ss);
    }

    if (n == "CloseServiceHandle") {
        SC_HANDLE h = (SC_HANDLE)p.raw[0];
        if (!h) return (DWORD_PTR)TRUE;
        return (DWORD_PTR)CloseServiceHandle(h);
    }

    return 0;
}
