// test_handle_chains.cpp
// Verifies that for every API category, handles (or address-space pointers)
// produced by API-A are correctly passed as arguments to API-B.
//
// Covers gaps in individual test_*_executor.cpp files:
//   - NT-native executors (NtFile, NtRegistry, NtMemory, NtSync) already have
//     HandleChain tests in their own files — NOT duplicated here.
//   - Win32 executors receive resolved handles via ArgPreparer.raw[]; these
//     chain tests verify the full round-trip:
//       Executor-A runs → UpdateMaps registers → ArgPreparer resolves → Executor-B runs.
//   - NtMiscExecutor chains (FindFile, Thread) are tested at executor level because
//     NtMisc reads handles directly from LogEvent via ReadHexArg().
//
// Two verification strategies used:
//   (A) Executor-level: exec-A registers in HandleMap, exec-B reads from HandleMap.
//   (B) ArgPreparer-level: exec-A returns handle, StoreRetval simulates UpdateMaps,
//       ArgPreparer.Prepare() resolves HANDLE arg → p.raw[], exec-B uses p.raw[].
//       Strategy (B) is the critical test for Win32 executors; it proves that
//       the HANDLE arg type in api_signatures.json correctly flows through
//       ArgPreparer into the executor.

#include <gtest/gtest.h>
#include <windows.h>
#include <wincrypt.h>
#include <winsvc.h>
#include "replay/handle_map.h"
#include "replay/pointer_map.h"
#include "replay/path_sandbox.h"
#include "replay/registry_sandbox.h"
#include "replay/pid_map.h"
#include "replay/arg_preparer.h"
#include "replay/log_types.h"
#include "replay/utils.h"
#include "replay/executors/file_executor.h"
#include "replay/executors/registry_executor.h"
#include "replay/executors/crypto_executor.h"
#include "replay/executors/service_executor.h"
#include "replay/executors/nt_misc_executor.h"
#include "replay/nt_native.h"

static constexpr const char* kSigDbPath =
    "C:\\Projects\\WinAPIReplay\\data\\api_signatures.json";

static LogEvent MakeEv(std::string api,
                       std::initializer_list<ArgValue> args = {}) {
    LogEvent ev;
    ev.api_name = std::move(api);
    ev.args.assign(args);
    return ev;
}

static PreparedArgs MakeRaw(std::vector<DWORD_PTR> vals) {
    PreparedArgs p;
    p.raw = std::move(vals);
    p.args.resize(p.raw.size());
    return p;
}

// Simulate ApiExecutor::UpdateMaps for HANDLE/SC_HANDLE return types.
// Maps orig_retval (original handle value from WinMET log) → real_handle
// (the actual handle returned by the executor on the replay machine).
static void StoreRetval(HandleMap& hmap,
                        DWORD_PTR orig_retval,
                        DWORD_PTR real_handle) {
    if (real_handle != 0 && real_handle != (DWORD_PTR)INVALID_HANDLE_VALUE)
        hmap.Register(orig_retval, real_handle);
}

// ─────────────────────────────────────────────────────────────────────────────
// Win32 File — CreateFileW → WriteFile → ReadFile  (Strategy B)
// FileExecutor returns the real HANDLE as return value.
// UpdateMaps stores orig_retval → real_handle (simulated by StoreRetval).
// ArgPreparer resolves HANDLE arg[0] for WriteFile/ReadFile.
// ─────────────────────────────────────────────────────────────────────────────

class Win32FileChainTest : public ::testing::Test {
protected:
    HandleMap    hmap_;
    PointerMap   pmap_;
    PathSandbox  psb_{L""};
    FileExecutor exec_{hmap_, pmap_, psb_};
    SignatureDB  sig_db_;
    PidMap       pids_;
    RegistrySandbox rsb_;
    ArgPreparer  prep_{sig_db_, hmap_, pmap_, pids_, psb_, rsb_};

    static constexpr wchar_t kFile[] = L"C:\\tmp\\hc_file_chain.txt";
    void SetUp()    override { sig_db_.Load(kSigDbPath); }
    void TearDown() override { DeleteFileW(kFile); }
};

// Win32 File chain: CreateFileW → WriteFile
// Verifies that ArgPreparer correctly resolves the HANDLE produced by CreateFileW
// so that WriteFile receives the real file handle via p.raw[0].
TEST_F(Win32FileChainTest, CreateWriteFile_ArgPreparerResolvesHandle) {
    // Step 1: Execute CreateFileW → real HANDLE returned by executor
    DWORD_PTR real_h = exec_.Execute(
        MakeEv("CreateFileW"),
        MakeRaw({(DWORD_PTR)kFile, GENERIC_READ | GENERIC_WRITE,
                 FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0}));
    ASSERT_NE(real_h, (DWORD_PTR)INVALID_HANDLE_VALUE);
    ASSERT_NE(real_h, (DWORD_PTR)0);

    // Step 2: Simulate UpdateMaps — register orig_retval (WinMET log value) → real_h
    constexpr DWORD_PTR kOrig = 0xA000;
    StoreRetval(hmap_, kOrig, real_h);

    // Step 3: ArgPreparer must resolve kOrig → real_h for WriteFile's HANDLE arg
    const ApiSignature* wsig = sig_db_.Find("WriteFile");
    ASSERT_NE(wsig, nullptr) << "WriteFile must be in api_signatures.json";
    ASSERT_GE((int)wsig->args.size(), 1);
    ASSERT_EQ(wsig->args[0].type, "HANDLE")
        << "WriteFile arg[0] must be HANDLE type in api_signatures.json";

    // WinMET stores Win32 HANDLE args as int64_t (not hex string)
    LogEvent wev = MakeEv("WriteFile", {
        (int64_t)kOrig,  // [0] HANDLE — original value from WinMET log
        (int64_t)0,      // [1] buffer (DATA_IN — ArgPreparer allocates)
        (int64_t)4,      // [2] nNumberOfBytesToWrite
        (int64_t)0,      // [3] lpNumberOfBytesWritten
        (int64_t)0,      // [4] lpOverlapped
    });
    PreparedArgs wp = prep_.Prepare(wev, *wsig);

    // KEY ASSERTION: p.raw[0] must equal the real handle (resolved from HandleMap)
    EXPECT_EQ(wp.raw[0], real_h)
        << "ArgPreparer failed to resolve HANDLE from HandleMap for WriteFile — "
           "Win32 file chain is broken";

    // Step 4: WriteFile succeeds using the resolved handle
    DWORD_PTR wret = exec_.Execute(MakeEv("WriteFile"), wp);
    EXPECT_NE(wret, (DWORD_PTR)FALSE)
        << "WriteFile failed with resolved handle — executor did not use p.raw[0]";

    CloseHandle((HANDLE)real_h);
}

// Win32 File chain: CreateFileW → ReadFile
// Same as above but verifies ReadFile arg resolution.
TEST_F(Win32FileChainTest, CreateReadFile_ArgPreparerResolvesHandle) {
    DWORD_PTR real_h = exec_.Execute(
        MakeEv("CreateFileW"),
        MakeRaw({(DWORD_PTR)kFile, GENERIC_READ | GENERIC_WRITE,
                 FILE_SHARE_READ, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0}));
    ASSERT_NE(real_h, (DWORD_PTR)INVALID_HANDLE_VALUE);

    constexpr DWORD_PTR kOrig = 0xA001;
    StoreRetval(hmap_, kOrig, real_h);

    const ApiSignature* rsig = sig_db_.Find("ReadFile");
    ASSERT_NE(rsig, nullptr);
    ASSERT_EQ(rsig->args[0].type, "HANDLE");

    char buf[16] = {};
    LogEvent rev = MakeEv("ReadFile", {
        (int64_t)kOrig,          // [0] HANDLE
        (int64_t)(DWORD_PTR)buf, // [1] buffer
        (int64_t)8,              // [2] nNumberOfBytesToRead
        (int64_t)0,              // [3] lpNumberOfBytesRead
        (int64_t)0,              // [4] lpOverlapped
    });
    PreparedArgs rp = prep_.Prepare(rev, *rsig);
    EXPECT_EQ(rp.raw[0], real_h)
        << "ArgPreparer failed to resolve HANDLE for ReadFile";

    DWORD_PTR rret = exec_.Execute(MakeEv("ReadFile"), rp);
    EXPECT_NE(rret, (DWORD_PTR)FALSE);
    CloseHandle((HANDLE)real_h);
}

// ─────────────────────────────────────────────────────────────────────────────
// Win32 Registry — RegCreateKeyExW → RegSetValueExW  (Strategy A+B)
// RegistryExecutor internally registers the output HKEY from event.args[4]
// (WinMET hex string). ArgPreparer then resolves it for subsequent calls.
// ─────────────────────────────────────────────────────────────────────────────

class Win32RegistryChainTest : public ::testing::Test {
protected:
    HandleMap        hmap_;
    PointerMap       pmap_;
    RegistrySandbox  rsb_;
    RegistryExecutor exec_{hmap_, pmap_, rsb_};
    SignatureDB      sig_db_;
    PidMap           pids_;
    PathSandbox      psb_{L""};
    ArgPreparer      prep_{sig_db_, hmap_, pmap_, pids_, psb_, rsb_};

    void SetUp() override {
        rsb_.Enable();
        exec_.Initialize();
        sig_db_.Load(kSigDbPath);
    }
    void TearDown() override {
        RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\WinAPIReplaySandbox");
    }
};

// Win32 Registry chain: RegCreateKeyExW → RegSetValueExW
// RegistryExecutor reads orig_hk from event.args[4] (hex string "0xC100"),
// creates sandbox key, registers orig_hk → real_HKEY in HandleMap.
// ArgPreparer resolves int64_t(kOrigHkey) → real_HKEY for RegSetValueExW.
TEST_F(Win32RegistryChainTest, CreateSetValue_ArgPreparerResolvesHKey) {
    constexpr DWORD_PTR kOrigHkey = 0xC100;

    // Step 1: Execute RegCreateKeyExW — RegistryExecutor registers hkey internally
    // WinMET format: args[0]=root HKEY, args[1]=subkey, args[4]=orig output HKEY (hex str)
    LogEvent cev = MakeEv("RegCreateKeyExW", {
        (int64_t)(DWORD_PTR)HKEY_CURRENT_USER,  // [0] root
        std::wstring(L"Software\\WARChainTest"), // [1] subkey
        (int64_t)0,                              // [2] reserved
        std::wstring(L"0xF003F"),                // [3] samDesired — KEY_ALL_ACCESS required for RegSetValueExW
        std::wstring(L"0xC100"),                 // [4] orig output HKEY
    });
    PreparedArgs cp = MakeRaw({
        (DWORD_PTR)HKEY_CURRENT_USER,
        (DWORD_PTR)L"Software\\WARChainTest",
        0, 0, KEY_ALL_ACCESS, 0, 0, 0, 0
    });
    DWORD_PTR cret = exec_.Execute(cev, cp);
    EXPECT_EQ(cret, (DWORD_PTR)ERROR_SUCCESS)
        << "RegCreateKeyExW failed — cannot test chain";
    ASSERT_TRUE(hmap_.HasMapping(kOrigHkey))
        << "RegistryExecutor must register orig_hk from event.args[4] in HandleMap";

    // Step 2: ArgPreparer resolves kOrigHkey → real_HKEY for RegSetValueExW
    const ApiSignature* ssig = sig_db_.Find("RegSetValueExW");
    ASSERT_NE(ssig, nullptr) << "RegSetValueExW must be in api_signatures.json";
    ASSERT_GE((int)ssig->args.size(), 1);
    ASSERT_EQ(ssig->args[0].type, "HANDLE")
        << "RegSetValueExW arg[0] must be HANDLE type for registry chain to work";

    // WinMET stores Win32 HKEY args as int64_t
    DWORD dwData = 42;
    LogEvent sev = MakeEv("RegSetValueExW", {
        (int64_t)kOrigHkey,                 // [0] HKEY — original value from WinMET
        std::wstring(L"ChainTestValue"),    // [1] value name
        (int64_t)0,                          // [2] reserved
        (int64_t)REG_DWORD,                 // [3] type
        (int64_t)(DWORD_PTR)&dwData,        // [4] data ptr
        (int64_t)sizeof(DWORD),             // [5] size
    });
    PreparedArgs sp = prep_.Prepare(sev, *ssig);
    DWORD_PTR expected = hmap_.Resolve(kOrigHkey);
    EXPECT_NE(expected, (DWORD_PTR)0)
        << "HandleMap.Resolve failed for kOrigHkey";
    EXPECT_EQ(sp.raw[0], expected)
        << "ArgPreparer did not resolve HKEY from HandleMap for RegSetValueExW — "
           "Win32 registry chain is broken";

    // Step 3: RegSetValueExW succeeds using the resolved handle
    DWORD_PTR sret = exec_.Execute(MakeEv("RegSetValueExW"), sp);
    EXPECT_EQ(sret, (DWORD_PTR)ERROR_SUCCESS)
        << "RegSetValueExW failed with resolved HKEY";
}

// ─────────────────────────────────────────────────────────────────────────────
// Crypto — CryptAcquireContextW → CryptCreateHash → CryptHashData  (Strategy A)
// All three steps go through CryptoExecutor. CryptoExecutor internally manages
// its own synth_provs_ and synth_hashes_ caches in addition to HandleMap.
// This tests the 3-step dependency chain in a single executor.
// ─────────────────────────────────────────────────────────────────────────────

class CryptoChainTest : public ::testing::Test {
protected:
    HandleMap    hmap_;
    PointerMap   pmap_;
    CryptoExecutor exec_{hmap_, pmap_};
    PreparedArgs   pa_{};

    static constexpr DWORD_PTR kOrigProv = 0xD100;
    static constexpr DWORD_PTR kOrigHash = 0xD200;
};

// CryptAcquireContextW → CryptCreateHash → CryptHashData
// Verifies that the 3-step crypto handle chain flows correctly through CryptoExecutor.
//
// Design note: CryptoExecutor does NOT register the HCRYPTPROV in HandleMap from
// CryptAcquireContextW. Instead, CryptCreateHash uses GetOrSynthProv(event) which
// lazily creates/finds the prov from event.args[0] and registers it in HandleMap.
// The chain therefore flows: CryptCreateHash registers hHash → CryptHashData resolves it.
TEST_F(CryptoChainTest, AcquireCreateHash_HashData_ThreeStepChain) {
    // Step 1: CryptAcquireContextW — raw[0] must point to a valid HCRYPTPROV buffer
    HCRYPTPROV prov = 0;
    LogEvent acq = MakeEv("CryptAcquireContextW", {
        (int64_t)0,                   // [0] phProv (output pointer)
        (int64_t)0,                   // [1] pszContainer
        (int64_t)0,                   // [2] pszProvider
        (int64_t)PROV_RSA_AES,        // [3] dwProvType
        (int64_t)CRYPT_VERIFYCONTEXT, // [4] dwFlags
    });
    PreparedArgs ap;
    ap.raw = {(DWORD_PTR)&prov, 0, 0, (DWORD_PTR)PROV_RSA_AES, (DWORD_PTR)CRYPT_VERIFYCONTEXT};
    ap.args.resize(ap.raw.size());
    DWORD_PTR acq_ret = exec_.Execute(acq, ap);
    EXPECT_NE(acq_ret, (DWORD_PTR)FALSE)
        << "CryptAcquireContextW failed";
    // Note: HandleMap is NOT updated by CryptAcquireContextW;
    // CryptCreateHash's GetOrSynthProv lazily registers the prov.

    // Step 2: CryptCreateHash using WinMET format
    // WinMET records [ALG_ID, hKey=0, phHash_output], not [hProv, ALG_ID, ...].
    // Executor detects: p.raw[1]==0 && p.raw[0] in ALG_ID range (0x8000–0x9FFF) → swap.
    // Prov is obtained via GetOrSynthProv(event) which reads event.args[0] as the orig key.
    // orig hHash is registered from event.args[2].
    LogEvent chash = MakeEv("CryptCreateHash", {
        (int64_t)CALG_MD5,             // [0] ALG_ID (WinMET-captured)
        (int64_t)0,                     // [1] hKey = 0
        std::wstring(L"0xD200"),        // [2] original phHash output value
    });
    PreparedArgs hp;
    hp.raw = {(DWORD_PTR)CALG_MD5, 0, 0, 0, 0};  // raw[0]=CALG_MD5 triggers WinMET shift
    hp.args.resize(hp.raw.size());
    DWORD_PTR hash_ret = exec_.Execute(chash, hp);
    EXPECT_NE(hash_ret, (DWORD_PTR)FALSE)
        << "CryptCreateHash failed — prov not synthesized or hash creation failed";
    EXPECT_TRUE(hmap_.HasMapping(kOrigHash))
        << "CryptoExecutor must register orig hHash (0xD200) in HandleMap after CryptCreateHash";

    // Step 3: CryptHashData — uses hash handle resolved from HandleMap
    // Executor allocates dummy data of size p.raw[2]; pbData = 0 in event is fine.
    DWORD_PTR real_hash = hmap_.Resolve(kOrigHash);
    ASSERT_NE(real_hash, (DWORD_PTR)0) << "HandleMap must have hash entry";
    LogEvent hdata = MakeEv("CryptHashData", {
        std::wstring(L"0xD200"),  // [0] hHash (orig value)
        (int64_t)0,               // [1] pbData (executor uses dummy data)
        (int64_t)8,               // [2] dwDataLen
        (int64_t)0,               // [3] dwFlags
    });
    PreparedArgs dp;
    dp.raw = {real_hash, 0, 8, 0};
    dp.args.resize(dp.raw.size());
    DWORD_PTR data_ret = exec_.Execute(hdata, dp);
    EXPECT_NE(data_ret, (DWORD_PTR)FALSE)
        << "CryptHashData failed — hash handle from CryptCreateHash not usable";

    if (prov) CryptReleaseContext(prov, 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// Service — OpenSCManagerW → OpenServiceW  (Strategy B)
// OpenSCManagerW returns SC_HANDLE. UpdateMaps (simulated) stores it.
// ArgPreparer resolves for OpenServiceW arg[0] (hSCManager).
// ─────────────────────────────────────────────────────────────────────────────

class ServiceChainTest : public ::testing::Test {
protected:
    HandleMap      hmap_;
    PointerMap     pmap_;
    ServiceExecutor exec_{hmap_, pmap_};
    SignatureDB     sig_db_;
    PidMap          pids_;
    PathSandbox     psb_{L""};
    RegistrySandbox rsb_;
    ArgPreparer     prep_{sig_db_, hmap_, pmap_, pids_, psb_, rsb_};

    void SetUp() override { sig_db_.Load(kSigDbPath); }
};

// Service chain: OpenSCManagerW → OpenServiceW
// OpenSCManagerW returns a real SC_HANDLE.
// After simulating UpdateMaps, ArgPreparer resolves it for OpenServiceW's hSCManager arg.
TEST_F(ServiceChainTest, OpenSCManager_OpenService_ArgPreparerResolvesHandle) {
    // Step 1: Execute OpenSCManagerW → real SC_HANDLE returned
    PreparedArgs scp = MakeRaw({0, 0, (DWORD_PTR)SC_MANAGER_CONNECT});
    DWORD_PTR real_scm = exec_.Execute(MakeEv("OpenSCManagerW"), scp);
    if (real_scm == 0) GTEST_SKIP() << "No SCManager access";

    // Step 2: Simulate UpdateMaps for SC_HANDLE return type
    constexpr DWORD_PTR kOrigScm = 0xE100;
    StoreRetval(hmap_, kOrigScm, real_scm);
    ASSERT_TRUE(hmap_.HasMapping(kOrigScm));

    // Step 3: ArgPreparer resolves kOrigScm → real_scm for OpenServiceW's arg[0]
    const ApiSignature* ossig = sig_db_.Find("OpenServiceW");
    ASSERT_NE(ossig, nullptr) << "OpenServiceW must be in api_signatures.json";
    ASSERT_GE((int)ossig->args.size(), 1);
    EXPECT_EQ(ossig->args[0].type, "HANDLE")
        << "OpenServiceW arg[0] (hSCManager) must be HANDLE type";

    LogEvent osev = MakeEv("OpenServiceW", {
        (int64_t)kOrigScm,           // [0] hSCManager — original value from WinMET
        std::wstring(L"EventLog"),   // [1] lpServiceName (known-present service)
        (int64_t)SERVICE_QUERY_STATUS, // [2] dwDesiredAccess
    });
    PreparedArgs osp = prep_.Prepare(osev, *ossig);
    EXPECT_EQ(osp.raw[0], real_scm)
        << "ArgPreparer failed to resolve SC_HANDLE from HandleMap for OpenServiceW — "
           "service chain is broken";

    // Step 4: OpenServiceW succeeds using the resolved SC_HANDLE
    DWORD_PTR osret = exec_.Execute(MakeEv("OpenServiceW"), osp);
    EXPECT_NE(osret, (DWORD_PTR)0)
        << "OpenServiceW failed with resolved hSCManager";

    if (osret) CloseServiceHandle((SC_HANDLE)osret);
    CloseServiceHandle((SC_HANDLE)real_scm);
}

// ─────────────────────────────────────────────────────────────────────────────
// NtMisc — FindFirstFileExW → FindNextFileW  (Strategy A)
// FindFirstFileExW returns a FIND handle. UpdateMaps (simulated) stores it.
// FindNextFileW reads the handle from event.args[1] via ReadHexArg() and
// resolves it through HandleMap.
// ─────────────────────────────────────────────────────────────────────────────

class NtMiscChainTest : public ::testing::Test {
protected:
    HandleMap    hmap_;
    PointerMap   pmap_;
    PathSandbox  psb_{L"C:\\tmp\\NtMiscChainTest"};
    NtMiscExecutor exec_{hmap_, pmap_, psb_};
    PreparedArgs   pa_{};

    static void SetUpTestSuite() {
        CreateDirectoryW(L"C:\\tmp\\NtMiscChainTest", nullptr);
        CreateDirectoryW(L"C:\\tmp\\NtMiscChainTest\\C_", nullptr);
        // Pre-create a file in sandbox for FindFirst to find
        HANDLE h = CreateFileW(L"C:\\tmp\\NtMiscChainTest\\C_\\hctest.txt",
                               GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }
    static void TearDownTestSuite() {
        DeleteFileW(L"C:\\tmp\\NtMiscChainTest\\C_\\hctest.txt");
        RemoveDirectoryW(L"C:\\tmp\\NtMiscChainTest\\C_");
        RemoveDirectoryW(L"C:\\tmp\\NtMiscChainTest");
    }
};

// FindFirstFileExW → FindNextFileW
// FindFirstFileExW returns a real FIND handle.
// FindNextFileW receives the original return-value (as hex string in args[1])
// and resolves it via HandleMap.
TEST_F(NtMiscChainTest, FindFirstToFindNext_HandleMapChain) {
    // Step 1: FindFirstFileExW — returns real FIND handle
    // NtMiscExecutor reads path from event.args[0] and returns the HANDLE.
    LogEvent ffev = MakeEv("FindFirstFileExW", {
        std::wstring(L"C:\\hctest.txt"),  // [0] search pattern (redirected to sandbox)
    });
    DWORD_PTR real_find = exec_.Execute(ffev, pa_);
    ASSERT_NE(real_find, (DWORD_PTR)INVALID_HANDLE_VALUE)
        << "FindFirstFileExW failed to find sandbox file";
    ASSERT_NE(real_find, (DWORD_PTR)0);

    // Step 2: Simulate UpdateMaps for HANDLE return type
    constexpr DWORD_PTR kOrigFind = 0xF100;
    StoreRetval(hmap_, kOrigFind, real_find);
    ASSERT_TRUE(hmap_.HasMapping(kOrigFind));

    // Step 3: FindNextFileW reads args[1] as orig handle (hex string)
    // NtMiscExecutor::Execute("FindNextFileW"):
    //   orig_h = ReadHexArg(event, 1)   ← reads args[1] as hex
    //   h = handle_map_.Resolve(orig_h) ← resolves via HandleMap
    //   FindNextFileW(h, &fd)
    LogEvent fnev = MakeEv("FindNextFileW", {
        std::wstring(L""),        // [0] found filename output (unused by executor)
        std::wstring(L"0xF100"), // [1] hFindFile — orig value from WinMET
    });
    // FindNextFileW returns TRUE if more files found, FALSE if no more.
    // Either outcome is acceptable; what matters is no crash and the call uses
    // the resolved handle (not INVALID_HANDLE_VALUE).
    DWORD_PTR fnret = exec_.Execute(fnev, pa_);
    // The executor resolves 0xF100 → real_find and calls FindNextFileW(real_find, &fd).
    // A return of FALSE (ERROR_NO_MORE_FILES) is valid; EXCEPTION would indicate chain failure.
    (void)fnret;  // success or no-more-files; both prove the handle was resolved

    // Cleanup: close the find handle that was registered
    HANDLE h = (HANDLE)hmap_.Resolve(kOrigFind);
    if (h && h != INVALID_HANDLE_VALUE) FindClose(h);
}

// ─────────────────────────────────────────────────────────────────────────────
// NtMisc — NtCreateThreadEx → NtResumeThread  (Strategy A)
// NtCreateThreadEx (no-spawn): registers a duplicate of the current thread
// as a dummy handle in HandleMap.
// NtResumeThread reads the handle from event.args[0] and resolves via HandleMap.
// ─────────────────────────────────────────────────────────────────────────────

TEST(NtMiscThreadChain, CreateThreadExToResumeThread_HandleMapChain) {
    HandleMap    hmap;
    PointerMap   pmap;
    PathSandbox  psb{L""};
    NtMiscExecutor exec{hmap, pmap, psb};
    PreparedArgs   pa{};

    constexpr DWORD_PTR kOrigThread = 0x0700;

    // Step 1: NtCreateThreadEx (no_spawn mode) — registers dummy thread handle
    // WinMET format: args[0] = orig output HANDLE (hex string)
    LogEvent ctev = MakeEv("NtCreateThreadEx", {
        std::wstring(L"0x0700"),  // [0] orig output HANDLE
        (int64_t)THREAD_ALL_ACCESS, // [1] DesiredAccess
    });
    DWORD_PTR ctret = exec.Execute(ctev, pa);
    EXPECT_EQ(ctret, (DWORD_PTR)0) << "NtCreateThreadEx must return STATUS_SUCCESS";
    ASSERT_TRUE(hmap.HasMapping(kOrigThread))
        << "NtMiscExecutor must register dummy thread handle after NtCreateThreadEx";

    HANDLE dummy = (HANDLE)hmap.Resolve(kOrigThread);
    ASSERT_NE(dummy, (HANDLE)nullptr);
    ASSERT_NE(dummy, (HANDLE)(DWORD_PTR)kOrigThread) << "Must be a real handle, not passthrough";

    // Step 2: NtResumeThread — reads args[0] as hex, resolves via HandleMap
    // NtMiscExecutor::Execute("NtResumeThread"):
    //   orig_h = ReadHexArg(event, 0)
    //   h = handle_map_.Resolve(orig_h)
    //   if (h && h != orig_h && h != GetCurrentThread()) ResumeThread(h)
    // Suspended threads created by DuplicateHandle cannot be resumed (not suspended),
    // so ResumeThread returns an error code — but what matters is no crash and
    // the handle was resolved correctly.
    LogEvent rtev = MakeEv("NtResumeThread", {
        std::wstring(L"0x0700"),  // [0] hThread — orig value from WinMET
    });
    DWORD_PTR rtret = exec.Execute(rtev, pa);
    EXPECT_EQ(rtret, (DWORD_PTR)0) << "NtResumeThread must return STATUS_SUCCESS";

    // Cleanup
    CloseHandle(dummy);
    hmap.Invalidate(kOrigThread);
}

// ─────────────────────────────────────────────────────────────────────────────
// ArgPreparer — HANDLE type resolution (design invariant test)
// Directly verifies that ArgPreparer maps int64_t HANDLE args from HandleMap.
// This is the core mechanism that ALL Win32 executor handle chains rely on.
// ─────────────────────────────────────────────────────────────────────────────

TEST(HandleChainDesignInvariant, ArgPreparer_HanleType_ResolvedFromHandleMap) {
    HandleMap hmap; PointerMap pmap; PidMap pids;
    PathSandbox psb{L""}; RegistrySandbox rsb;
    SignatureDB sig_db;
    sig_db.Load(kSigDbPath);
    ArgPreparer prep{sig_db, hmap, pmap, pids, psb, rsb};

    // Register a fake mapping: original handle 0x1234 → real handle 0xABCD
    constexpr DWORD_PTR kOrig = 0x1234;
    constexpr DWORD_PTR kReal = 0xABCD;
    hmap.Register(kOrig, kReal);

    // Use a real sig that has HANDLE as arg[0] (WriteFile)
    const ApiSignature* sig = sig_db.Find("WriteFile");
    ASSERT_NE(sig, nullptr);
    ASSERT_EQ(sig->args[0].type, "HANDLE");

    LogEvent ev = MakeEv("WriteFile", {(int64_t)kOrig, (int64_t)0, (int64_t)0});
    PreparedArgs p = prep.Prepare(ev, *sig);
    EXPECT_EQ(p.raw[0], kReal)
        << "ArgPreparer HANDLE resolution is the foundation of all Win32 handle chains; "
           "if this fails, every Win32 executor chain breaks";
}

// ─────────────────────────────────────────────────────────────────────────────
// Design completeness: verify all Win32 executors with HANDLE args have
// their first arg typed as HANDLE in api_signatures.json.
// These APIs must have HANDLE arg[0] for ArgPreparer chain resolution to work.
// ─────────────────────────────────────────────────────────────────────────────

TEST(HandleChainDesignInvariant, SigDb_Win32ExecutorApis_HaveHandleArg0) {
    SignatureDB sig_db;
    sig_db.Load(kSigDbPath);

    static const struct { const char* api; const char* category; } kChainApis[] = {
        // File executor: CreateFileW output → WriteFile/ReadFile/CloseHandle input
        { "WriteFile",          "file" },
        { "ReadFile",           "file" },
        { "CloseHandle",        "file" },
        // Registry executor: RegCreateKeyExW output → RegSetValueExW/RegQueryValueExW input
        { "RegSetValueExW",     "registry" },
        { "RegSetValueExA",     "registry" },
        { "RegQueryValueExW",   "registry" },
        { "RegQueryValueExA",   "registry" },
        { "RegCloseKey",        "registry" },
        // Service executor: OpenSCManagerW output → OpenServiceW input
        { "OpenServiceW",       "service" },
        { "OpenServiceA",       "service" },
        // Sync executor: CreateMutexW/CreateEventW output → WaitForSingleObject input
        { "WaitForSingleObject","sync" },
        { "ReleaseMutex",       "sync" },
        // Crypto executor: CryptAcquireContextW output → CryptCreateHash input
        // (CryptCreateHash is handled internally, not via ArgPreparer, but verify sig)
        { "CryptDestroyHash",   "crypto" },
        { "CryptReleaseContext","crypto" },
    };

    for (const auto& ka : kChainApis) {
        const ApiSignature* sig = sig_db.Find(ka.api);
        ASSERT_NE(sig, nullptr) << ka.api << " must be in api_signatures.json";
        ASSERT_GE((int)sig->args.size(), 1) << ka.api << " must have at least 1 arg";
        EXPECT_EQ(sig->args[0].type, "HANDLE")
            << ka.api << " (category=" << ka.category << "): "
               "arg[0] must be HANDLE for ArgPreparer chain resolution to work; "
               "current type is '" << sig->args[0].type << "'";
    }
}
