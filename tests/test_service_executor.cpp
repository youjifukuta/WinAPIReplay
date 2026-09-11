// Tests for ServiceExecutor: all 10 APIs in SupportedApis().
// ServiceExecutor uses p.raw[] for args.
// CreateServiceW/A require elevated privileges → skip gracefully on failure.
#include <gtest/gtest.h>
#include <windows.h>
#include <winsvc.h>
#include "replay/handle_map.h"
#include "replay/pointer_map.h"
#include "replay/executors/service_executor.h"
#include "replay/log_types.h"
#include "replay/arg_preparer.h"

static LogEvent MakeEvent(std::string api) {
    LogEvent ev;
    ev.api_name = std::move(api);
    return ev;
}

static PreparedArgs MakeRaw(std::vector<DWORD_PTR> vals) {
    PreparedArgs p;
    p.raw = std::move(vals);
    p.args.resize(p.raw.size());
    return p;
}

class ServiceExecutorTest : public ::testing::Test {
protected:
    HandleMap       hmap_;
    PointerMap      pmap_;
    ServiceExecutor exec_{hmap_, pmap_};
};

// ── OpenSCManagerW ────────────────────────────────────────────────────────────

TEST_F(ServiceExecutorTest, OpenSCManagerW_ReturnsHandle) {
    auto p = MakeRaw({0, 0, SC_MANAGER_CONNECT});
    DWORD_PTR ret = exec_.Execute(MakeEvent("OpenSCManagerW"), p);
    SC_HANDLE h = (SC_HANDLE)ret;
    EXPECT_NE(h, (SC_HANDLE)nullptr);
    if (h) CloseServiceHandle(h);
}

TEST_F(ServiceExecutorTest, OpenSCManagerW_ZeroAccess_FallsBackToConnect) {
    // access=0 → executor substitutes SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE
    auto p = MakeRaw({0, 0, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("OpenSCManagerW"), p);
    SC_HANDLE h = (SC_HANDLE)ret;
    EXPECT_NE(h, (SC_HANDLE)nullptr);
    if (h) CloseServiceHandle(h);
}

// ── OpenSCManagerA ────────────────────────────────────────────────────────────

TEST_F(ServiceExecutorTest, OpenSCManagerA_ReturnsHandle) {
    auto p = MakeRaw({0, 0, SC_MANAGER_CONNECT});
    DWORD_PTR ret = exec_.Execute(MakeEvent("OpenSCManagerA"), p);
    SC_HANDLE h = (SC_HANDLE)ret;
    EXPECT_NE(h, (SC_HANDLE)nullptr);
    if (h) CloseServiceHandle(h);
}

// ── OpenServiceW ──────────────────────────────────────────────────────────────

TEST_F(ServiceExecutorTest, OpenServiceW_KnownService_ReturnsHandle) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) GTEST_SKIP() << "No SCM access";

    // "EventLog" is guaranteed to exist on all Windows versions
    auto p = MakeRaw({(DWORD_PTR)scm, (DWORD_PTR)L"EventLog", SERVICE_QUERY_STATUS});
    DWORD_PTR ret = exec_.Execute(MakeEvent("OpenServiceW"), p);
    SC_HANDLE h = (SC_HANDLE)ret;
    EXPECT_NE(h, (SC_HANDLE)nullptr);
    if (h) CloseServiceHandle(h);
    CloseServiceHandle(scm);
}

TEST_F(ServiceExecutorTest, OpenServiceW_UnknownService_SynthesizesFallback) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) GTEST_SKIP() << "No SCM access";

    // Non-existent service → executor substitutes a known-present fallback (EventLog etc.)
    auto p = MakeRaw({(DWORD_PTR)scm, (DWORD_PTR)L"XYZNonExistentSvc123", SERVICE_QUERY_STATUS});
    DWORD_PTR ret = exec_.Execute(MakeEvent("OpenServiceW"), p);
    SC_HANDLE h = (SC_HANDLE)ret;
    EXPECT_NE(h, (SC_HANDLE)nullptr);
    if (h) CloseServiceHandle(h);
    CloseServiceHandle(scm);
}

TEST_F(ServiceExecutorTest, OpenServiceW_NullScm_SynthesizesFallback) {
    // hScm=null → executor opens its own SCM internally
    auto p = MakeRaw({0, (DWORD_PTR)L"EventLog", SERVICE_QUERY_STATUS});
    DWORD_PTR ret = exec_.Execute(MakeEvent("OpenServiceW"), p);
    SC_HANDLE h = (SC_HANDLE)ret;
    EXPECT_NE(h, (SC_HANDLE)nullptr);
    if (h) CloseServiceHandle(h);
}

// ── OpenServiceA ──────────────────────────────────────────────────────────────

TEST_F(ServiceExecutorTest, OpenServiceA_KnownService_ReturnsHandle) {
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) GTEST_SKIP() << "No SCM access";
    auto p = MakeRaw({(DWORD_PTR)scm, (DWORD_PTR)"EventLog", SERVICE_QUERY_STATUS});
    DWORD_PTR ret = exec_.Execute(MakeEvent("OpenServiceA"), p);
    SC_HANDLE h = (SC_HANDLE)ret;
    EXPECT_NE(h, (SC_HANDLE)nullptr);
    if (h) CloseServiceHandle(h);
    CloseServiceHandle(scm);
}

// ── CreateServiceW ────────────────────────────────────────────────────────────

TEST_F(ServiceExecutorTest, CreateServiceW_NullScm_ReturnsNull) {
    // hScm=null → executor returns nullptr immediately (no access)
    PreparedArgs p;
    p.raw.resize(13, 0);
    p.args.resize(13);
    DWORD_PTR ret = exec_.Execute(MakeEvent("CreateServiceW"), p);
    EXPECT_EQ(ret, (DWORD_PTR)nullptr);
}

TEST_F(ServiceExecutorTest, CreateServiceW_ValidScm_DoesNotInstallRealService) {
    // Core safety invariant: even with a valid SCM handle, the stub must NOT
    // write to the SCM database.  The returned handle must be a synth handle to
    // an existing benign service, not the malware-named service.
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr,
                                   SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) GTEST_SKIP() << "No SCM access";

    static const wchar_t kFakeName[] = L"WinAPIReplaySafetyTest_XYZ_99999";
    PreparedArgs p;
    p.raw.resize(13, 0);
    p.args.resize(13);
    p.raw[0] = (DWORD_PTR)scm;
    p.raw[1] = (DWORD_PTR)kFakeName;

    DWORD_PTR ret = exec_.Execute(MakeEvent("CreateServiceW"), p);
    SC_HANDLE hSvc = (SC_HANDLE)ret;

    // Stub returns a non-NULL synth handle to a known-benign service
    EXPECT_NE(hSvc, (SC_HANDLE)nullptr)
        << "Stub should synthesize a handle for downstream ControlService calls";

    // The malware-named service must NOT exist in the SCM database
    SC_HANDLE hCheck = OpenServiceW(scm, kFakeName, SERVICE_QUERY_STATUS);
    EXPECT_EQ(hCheck, (SC_HANDLE)nullptr)
        << "Stub must NOT install a real service with the malware-supplied name";

    if (hSvc)   CloseServiceHandle(hSvc);
    if (hCheck) CloseServiceHandle(hCheck);
    CloseServiceHandle(scm);
}

// ── CreateServiceA ────────────────────────────────────────────────────────────

TEST_F(ServiceExecutorTest, CreateServiceA_NullScm_ReturnsNull) {
    PreparedArgs p;
    p.raw.resize(13, 0);
    p.args.resize(13);
    DWORD_PTR ret = exec_.Execute(MakeEvent("CreateServiceA"), p);
    EXPECT_EQ(ret, (DWORD_PTR)nullptr);
}

TEST_F(ServiceExecutorTest, CreateServiceA_ValidScm_DoesNotInstallRealService) {
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr,
                                   SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) GTEST_SKIP() << "No SCM access";

    static const char kFakeName[] = "WinAPIReplaySafetyTest_XYZ_99999";
    PreparedArgs p;
    p.raw.resize(13, 0);
    p.args.resize(13);
    p.raw[0] = (DWORD_PTR)scm;
    p.raw[1] = (DWORD_PTR)kFakeName;

    DWORD_PTR ret = exec_.Execute(MakeEvent("CreateServiceA"), p);
    SC_HANDLE hSvc = (SC_HANDLE)ret;

    EXPECT_NE(hSvc, (SC_HANDLE)nullptr);

    SC_HANDLE hCheck = OpenServiceA(scm, kFakeName, SERVICE_QUERY_STATUS);
    EXPECT_EQ(hCheck, (SC_HANDLE)nullptr)
        << "Stub must NOT install a real service with the malware-supplied name";

    if (hSvc)   CloseServiceHandle(hSvc);
    if (hCheck) CloseServiceHandle(hCheck);
    CloseServiceHandle(scm);
}

// ── StartServiceW ─────────────────────────────────────────────────────────────

TEST_F(ServiceExecutorTest, StartServiceW_NullHandle_ReturnsTRUE) {
    auto p = MakeRaw({0, 0, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("StartServiceW"), p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
}

TEST_F(ServiceExecutorTest, StartServiceW_ValidHandle_ReturnsTRUEWithoutChangingState) {
    // Stub must return TRUE and must NOT call the real StartServiceW.
    // Verify by querying the service status before and after: state must be unchanged.
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) GTEST_SKIP() << "No SCM access";
    SC_HANDLE hSvc = OpenServiceW(scm, L"EventLog", SERVICE_QUERY_STATUS);
    if (!hSvc) { CloseServiceHandle(scm); GTEST_SKIP() << "Cannot open EventLog"; }

    SERVICE_STATUS before{};
    QueryServiceStatus(hSvc, &before);

    auto p = MakeRaw({(DWORD_PTR)hSvc, 0, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("StartServiceW"), p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE) << "Stub must return TRUE";

    SERVICE_STATUS after{};
    QueryServiceStatus(hSvc, &after);
    EXPECT_EQ(after.dwCurrentState, before.dwCurrentState)
        << "Stub must not change service state (real StartServiceW not called)";

    CloseServiceHandle(hSvc);
    CloseServiceHandle(scm);
}

// ── StartServiceA ─────────────────────────────────────────────────────────────

TEST_F(ServiceExecutorTest, StartServiceA_NullHandle_ReturnsTRUE) {
    auto p = MakeRaw({0, 0, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("StartServiceA"), p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
}

TEST_F(ServiceExecutorTest, StartServiceA_ValidHandle_ReturnsTRUEWithoutChangingState) {
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) GTEST_SKIP() << "No SCM access";
    SC_HANDLE hSvc = OpenServiceA(scm, "EventLog", SERVICE_QUERY_STATUS);
    if (!hSvc) { CloseServiceHandle(scm); GTEST_SKIP() << "Cannot open EventLog"; }

    SERVICE_STATUS before{};
    QueryServiceStatus(hSvc, &before);

    auto p = MakeRaw({(DWORD_PTR)hSvc, 0, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("StartServiceA"), p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE) << "Stub must return TRUE";

    SERVICE_STATUS after{};
    QueryServiceStatus(hSvc, &after);
    EXPECT_EQ(after.dwCurrentState, before.dwCurrentState)
        << "Stub must not change service state";

    CloseServiceHandle(hSvc);
    CloseServiceHandle(scm);
}

// ── ControlService ────────────────────────────────────────────────────────────

TEST_F(ServiceExecutorTest, ControlService_NullHandle_ReturnsTRUE) {
    SERVICE_STATUS ss{};
    auto p = MakeRaw({0, SERVICE_CONTROL_INTERROGATE, (DWORD_PTR)&ss});
    DWORD_PTR ret = exec_.Execute(MakeEvent("ControlService"), p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
}

// ── CloseServiceHandle ────────────────────────────────────────────────────────

TEST_F(ServiceExecutorTest, CloseServiceHandle_NullHandle_ReturnsTRUE) {
    auto p = MakeRaw({0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("CloseServiceHandle"), p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
}

TEST_F(ServiceExecutorTest, CloseServiceHandle_ValidHandle_Succeeds) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) GTEST_SKIP() << "No SCM access";
    auto p = MakeRaw({(DWORD_PTR)scm});
    DWORD_PTR ret = exec_.Execute(MakeEvent("CloseServiceHandle"), p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
}

// ── Unknown API returns 0 ─────────────────────────────────────────────────────

TEST_F(ServiceExecutorTest, UnknownApi_ReturnsZero) {
    PreparedArgs p;
    DWORD_PTR ret = exec_.Execute(MakeEvent("ServiceUnknown"), p);
    EXPECT_EQ(ret, (DWORD_PTR)0);
}
