#include <gtest/gtest.h>
#include "replay/arg_preparer.h"
#include "replay/handle_map.h"
#include "replay/pointer_map.h"
#include "replay/pid_map.h"
#include "replay/path_sandbox.h"
#include "replay/registry_sandbox.h"
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

// Helper: build a minimal SignatureDB from an in-memory API entry.
// Serializes all ArgSpec fields; f.close() is called before Load().
static SignatureDB MakeDb(const std::string& api_name,
                          const std::vector<ArgSpec>& args,
                          const std::string& ret = "BOOL",
                          const std::string& category = "test") {
    std::string tmp = (fs::temp_directory_path() / "sig_test.json").string();
    std::ofstream f(tmp, std::ios::trunc);
    f << "{\"_meta\":{},\"" << api_name << "\":{\"module\":\"test\","
      << "\"category\":\"" << category << "\",\"return_type\":\"" << ret << "\","
      << "\"out_handle\":null,\"invalidates_arg\":null,\"args\":[";
    bool first = true;
    for (const auto& a : args) {
        if (!first) f << ",";
        // Emit as JSON object when any non-default field is present
        bool needs_obj = (a.size_bytes > 0) || (a.size_arg >= 0) || (a.default_size != 65536);
        if (needs_obj) {
            f << "{\"type\":\"" << a.type << "\"";
            if (a.size_bytes > 0)        f << ",\"size_bytes\":"   << a.size_bytes;
            if (a.size_arg >= 0)         f << ",\"size_arg\":"     << a.size_arg;
            if (a.default_size != 65536) f << ",\"default_size\":" << a.default_size;
            f << "}";
        } else {
            f << "\"" << a.type << "\"";
        }
        first = false;
    }
    f << "]}}";
    f.close();
    SignatureDB db;
    db.Load(tmp);
    return db;
}

static ArgPreparer MakePreparer(SignatureDB& db,
                                HandleMap& hmap, PointerMap& pmap, PidMap& pidmap,
                                PathSandbox& ps, RegistrySandbox& rs) {
    return ArgPreparer(db, hmap, pmap, pidmap, ps, rs);
}

// Helper: make a LogEvent with given args
static LogEvent MakeEvent(const std::string& api,
                           std::vector<ArgValue> args = {}) {
    LogEvent e{};
    e.seq = 1;
    e.api_name = api;
    e.args = std::move(args);
    e.return_val = "0x0";
    return e;
}

// ── DIRECT arg ────────────────────────────────────────────────────────────

TEST(ArgPreparer, DirectIntArg) {
    HandleMap hm; PointerMap pm; PidMap pidm;
    PathSandbox ps{L""}; RegistrySandbox rs;
    auto db = MakeDb("TestDirect", {ArgSpec{"DIRECT"}});
    auto prep = MakePreparer(db, hm, pm, pidm, ps, rs);
    const auto* sig = db.Find("TestDirect");
    ASSERT_NE(sig, nullptr);

    auto ev = MakeEvent("TestDirect", {(std::int64_t)42});
    auto p = prep.Prepare(ev, *sig);
    ASSERT_EQ(p.raw.size(), 1u);
    EXPECT_EQ(p.raw[0], (DWORD_PTR)42);
}

// ── WSTRING arg ───────────────────────────────────────────────────────────

TEST(ArgPreparer, WStringArg) {
    HandleMap hm; PointerMap pm; PidMap pidm;
    PathSandbox ps{L""}; RegistrySandbox rs;
    auto db = MakeDb("TestWStr", {ArgSpec{"WSTRING"}});
    auto prep = MakePreparer(db, hm, pm, pidm, ps, rs);
    const auto* sig = db.Find("TestWStr");

    auto ev = MakeEvent("TestWStr", {std::wstring(L"hello")});
    auto p = prep.Prepare(ev, *sig);
    ASSERT_EQ(p.raw.size(), 1u);
    ASSERT_NE(p.raw[0], 0u);
    EXPECT_EQ(std::wstring(reinterpret_cast<const wchar_t*>(p.raw[0])), L"hello");
}

// ── ASTRING arg ───────────────────────────────────────────────────────────

TEST(ArgPreparer, AStringArg) {
    HandleMap hm; PointerMap pm; PidMap pidm;
    PathSandbox ps{L""}; RegistrySandbox rs;
    auto db = MakeDb("TestAStr", {ArgSpec{"ASTRING"}});
    auto prep = MakePreparer(db, hm, pm, pidm, ps, rs);
    const auto* sig = db.Find("TestAStr");

    auto ev = MakeEvent("TestAStr", {std::wstring(L"hello")});
    auto p = prep.Prepare(ev, *sig);
    ASSERT_EQ(p.raw.size(), 1u);
    ASSERT_NE(p.raw[0], (DWORD_PTR)0);
    // Wide→ANSI conversion; ASCII chars are identical in CP_ACP
    EXPECT_STREQ(reinterpret_cast<const char*>(p.raw[0]), "hello");
}

TEST(ArgPreparer, AStringPathSandboxRedirectsForFileCategory) {
    HandleMap hm; PointerMap pm; PidMap pidm;
    PathSandbox ps{L"C:\\Sandbox"}; RegistrySandbox rs;
    auto db = MakeDb("CreateFileA", {ArgSpec{"ASTRING"}}, "HANDLE", "file");
    auto prep = MakePreparer(db, hm, pm, pidm, ps, rs);
    const auto* sig = db.Find("CreateFileA");

    auto ev = MakeEvent("CreateFileA", {std::wstring(L"C:\\Users\\victim\\evil.exe")});
    auto p = prep.Prepare(ev, *sig);

    ASSERT_EQ(p.transforms.size(), 1u);
    EXPECT_EQ(p.transforms[0].param_index, 0);
    EXPECT_EQ(p.transforms[0].original,  "C:\\Users\\victim\\evil.exe");
    EXPECT_EQ(p.transforms[0].rewritten, "C:\\Sandbox\\C_\\Users\\victim\\evil.exe");
    EXPECT_STREQ(reinterpret_cast<const char*>(p.raw[0]),
                 "C:\\Sandbox\\C_\\Users\\victim\\evil.exe");
}

TEST(ArgPreparer, AStringPathSandboxEmptyWhenDisabled) {
    HandleMap hm; PointerMap pm; PidMap pidm;
    PathSandbox ps{L""}; RegistrySandbox rs;
    auto db = MakeDb("CreateFileA", {ArgSpec{"ASTRING"}}, "HANDLE", "file");
    auto prep = MakePreparer(db, hm, pm, pidm, ps, rs);
    const auto* sig = db.Find("CreateFileA");

    auto ev = MakeEvent("CreateFileA", {std::wstring(L"C:\\Users\\victim\\evil.exe")});
    auto p = prep.Prepare(ev, *sig);

    EXPECT_TRUE(p.transforms.empty());
    EXPECT_STREQ(reinterpret_cast<const char*>(p.raw[0]), "C:\\Users\\victim\\evil.exe");
}

TEST(ArgPreparer, AStringNoSandboxForNonFileCategory) {
    HandleMap hm; PointerMap pm; PidMap pidm;
    PathSandbox ps{L"C:\\Sandbox"}; RegistrySandbox rs;
    auto db = MakeDb("LoadLibraryA", {ArgSpec{"ASTRING"}}, "HMODULE", "dll");
    auto prep = MakePreparer(db, hm, pm, pidm, ps, rs);
    const auto* sig = db.Find("LoadLibraryA");

    auto ev = MakeEvent("LoadLibraryA", {std::wstring(L"C:\\Users\\victim\\evil.dll")});
    auto p = prep.Prepare(ev, *sig);

    EXPECT_TRUE(p.transforms.empty());
}

// ── NULL_OR_PTR arg ───────────────────────────────────────────────────────

TEST(ArgPreparer, NullOrPtrIsZero) {
    HandleMap hm; PointerMap pm; PidMap pidm;
    PathSandbox ps{L""}; RegistrySandbox rs;
    auto db = MakeDb("TestNull", {ArgSpec{"NULL_OR_PTR"}});
    auto prep = MakePreparer(db, hm, pm, pidm, ps, rs);
    const auto* sig = db.Find("TestNull");

    auto ev = MakeEvent("TestNull", {std::nullptr_t{}});
    auto p = prep.Prepare(ev, *sig);
    EXPECT_EQ(p.raw[0], (DWORD_PTR)0);
}

// ── DATA_IN arg ───────────────────────────────────────────────────────────

TEST(ArgPreparer, DataInAllocatesBuffer) {
    HandleMap hm; PointerMap pm; PidMap pidm;
    PathSandbox ps{L""}; RegistrySandbox rs;
    ArgSpec spec{"DATA_IN"};
    spec.size_bytes = 32;
    auto db = MakeDb("TestDataIn", {spec});
    auto prep = MakePreparer(db, hm, pm, pidm, ps, rs);
    const auto* sig = db.Find("TestDataIn");

    auto ev = MakeEvent("TestDataIn");
    auto p = prep.Prepare(ev, *sig);
    ASSERT_EQ(p.args.size(), 1u);
    EXPECT_EQ(p.args[0].buffer.size(), 32u);
    EXPECT_NE(p.raw[0], (DWORD_PTR)0);
}

// ── DATA_OUT arg ──────────────────────────────────────────────────────────

TEST(ArgPreparer, DataOutAllocatesBuffer) {
    HandleMap hm; PointerMap pm; PidMap pidm;
    PathSandbox ps{L""}; RegistrySandbox rs;
    ArgSpec spec{"DATA_OUT"};
    spec.size_bytes = 64;
    auto db = MakeDb("TestDataOut", {spec});
    auto prep = MakePreparer(db, hm, pm, pidm, ps, rs);
    const auto* sig = db.Find("TestDataOut");

    auto ev = MakeEvent("TestDataOut", {std::nullptr_t{}});
    auto p = prep.Prepare(ev, *sig);
    ASSERT_EQ(p.args.size(), 1u);
    EXPECT_EQ(p.args[0].buffer.size(), 64u);
    EXPECT_NE(p.raw[0], (DWORD_PTR)0);
}

// ── SIZE_INOUT arg ────────────────────────────────────────────────────────

TEST(ArgPreparer, SizeInoutBuffer) {
    HandleMap hm; PointerMap pm; PidMap pidm;
    PathSandbox ps{L""}; RegistrySandbox rs;
    ArgSpec spec{"SIZE_INOUT"};
    spec.default_size = 512;  // non-default value to verify it's used
    auto db = MakeDb("TestSizeInout", {spec});
    auto prep = MakePreparer(db, hm, pm, pidm, ps, rs);
    const auto* sig = db.Find("TestSizeInout");

    auto ev = MakeEvent("TestSizeInout");
    auto p = prep.Prepare(ev, *sig);
    ASSERT_EQ(p.args.size(), 1u);
    EXPECT_EQ(p.args[0].buffer.size(), sizeof(DWORD));
    ASSERT_NE(p.raw[0], (DWORD_PTR)0);
    EXPECT_EQ(*reinterpret_cast<const DWORD*>(p.raw[0]), (DWORD)512);
}

// ── ADDR_PTR arg ──────────────────────────────────────────────────────────

TEST(ArgPreparer, AddrPtrIsZero) {
    HandleMap hm; PointerMap pm; PidMap pidm;
    PathSandbox ps{L""}; RegistrySandbox rs;
    auto db = MakeDb("TestAddrPtr", {ArgSpec{"ADDR_PTR"}});
    auto prep = MakePreparer(db, hm, pm, pidm, ps, rs);
    const auto* sig = db.Find("TestAddrPtr");

    // NetworkExecutor bypasses this at call time; ArgPreparer always produces 0
    auto ev = MakeEvent("TestAddrPtr", {(std::int64_t)0x12345678});
    auto p = prep.Prepare(ev, *sig);
    EXPECT_EQ(p.raw[0], (DWORD_PTR)0);
}

// ── PTR_OUT arg ───────────────────────────────────────────────────────────

TEST(ArgPreparer, PtrOutAllocatesBuffer) {
    HandleMap hm; PointerMap pm; PidMap pidm;
    PathSandbox ps{L""}; RegistrySandbox rs;
    auto db = MakeDb("TestPtrOut", {ArgSpec{"PTR_OUT"}});
    auto prep = MakePreparer(db, hm, pm, pidm, ps, rs);
    const auto* sig = db.Find("TestPtrOut");

    auto ev = MakeEvent("TestPtrOut");
    auto p = prep.Prepare(ev, *sig);
    ASSERT_EQ(p.args.size(), 1u);
    EXPECT_EQ(p.args[0].buffer.size(), sizeof(void*));
    EXPECT_NE(p.raw[0], (DWORD_PTR)0);
}

// ── HANDLE_ARRAY arg ──────────────────────────────────────────────────────

TEST(ArgPreparer, HandleArrayFromInlineHandles) {
    HandleMap hm; PointerMap pm; PidMap pidm;
    PathSandbox ps{L""}; RegistrySandbox rs;
    hm.Register((DWORD_PTR)0x10, (DWORD_PTR)0xAA);
    hm.Register((DWORD_PTR)0x20, (DWORD_PTR)0xBB);

    auto db = MakeDb("TestHandleArr", {ArgSpec{"HANDLE_ARRAY"}});
    auto prep = MakePreparer(db, hm, pm, pidm, ps, rs);
    const auto* sig = db.Find("TestHandleArr");

    auto ev = MakeEvent("TestHandleArr");
    ev.inline_handles = {"0x10", "0x20"};
    auto p = prep.Prepare(ev, *sig);
    ASSERT_EQ(p.args[0].handle_arr.size(), 2u);
    EXPECT_EQ((DWORD_PTR)p.args[0].handle_arr[0], (DWORD_PTR)0xAA);
    EXPECT_EQ((DWORD_PTR)p.args[0].handle_arr[1], (DWORD_PTR)0xBB);
    EXPECT_EQ(p.raw[0], reinterpret_cast<DWORD_PTR>(p.args[0].handle_arr.data()));
}

TEST(ArgPreparer, HandleArrayEmptyWhenNoInlineHandles) {
    HandleMap hm; PointerMap pm; PidMap pidm;
    PathSandbox ps{L""}; RegistrySandbox rs;
    auto db = MakeDb("TestHandleArrEmpty", {ArgSpec{"HANDLE_ARRAY"}});
    auto prep = MakePreparer(db, hm, pm, pidm, ps, rs);
    const auto* sig = db.Find("TestHandleArrEmpty");

    auto ev = MakeEvent("TestHandleArrEmpty");
    // No inline_handles → raw[0] = 0 (signals [APPROX] to ApiExecutor)
    auto p = prep.Prepare(ev, *sig);
    EXPECT_EQ(p.raw[0], (DWORD_PTR)0);
    EXPECT_TRUE(p.args[0].handle_arr.empty());
}

// ── HANDLE resolve ────────────────────────────────────────────────────────

TEST(ArgPreparer, HandleResolvedFromMap) {
    HandleMap hm; PointerMap pm; PidMap pidm;
    PathSandbox ps{L""}; RegistrySandbox rs;
    auto db = MakeDb("TestHandle", {ArgSpec{"HANDLE"}});
    auto prep = MakePreparer(db, hm, pm, pidm, ps, rs);
    const auto* sig = db.Find("TestHandle");

    HANDLE real = (HANDLE)0xDEADull;
    hm.Register((DWORD_PTR)0x4, (DWORD_PTR)real);

    auto ev = MakeEvent("TestHandle", {(std::int64_t)0x4});
    auto p = prep.Prepare(ev, *sig);
    EXPECT_EQ((HANDLE)p.raw[0], real);
}

TEST(ArgPreparer, PredefinedHkeyPassesThrough) {
    HandleMap hm; PointerMap pm; PidMap pidm;
    PathSandbox ps{L""}; RegistrySandbox rs;
    auto db = MakeDb("TestPredefined", {ArgSpec{"HANDLE"}});
    auto prep = MakePreparer(db, hm, pm, pidm, ps, rs);
    const auto* sig = db.Find("TestPredefined");

    // Register should be silently ignored for predefined values
    hm.Register((DWORD_PTR)0x80000002ULL, (DWORD_PTR)0x99999999ULL);

    // 32-bit log form "0x80000002" must be normalized to the proper 64-bit HKEY constant.
    // On 64-bit Windows, HKEY_LOCAL_MACHINE == (HKEY)0xFFFFFFFF80000002 (sign-extended).
    // Passing the raw 0x80000002 to registry APIs would yield ERROR_INVALID_HANDLE.
    auto ev = MakeEvent("TestPredefined", {(std::int64_t)0x80000002LL});
    auto p = prep.Prepare(ev, *sig);
    EXPECT_EQ(p.raw[0], (DWORD_PTR)HKEY_LOCAL_MACHINE);
}

// ── REGISTRY_SUBKEY arg ───────────────────────────────────────────────────

TEST(ArgPreparer, RegistrySubkeyRedirectsWithSandbox) {
    HandleMap hm; PointerMap pm; PidMap pidm;
    PathSandbox ps{L""};
    RegistrySandbox rs;
    rs.Enable();

    // Two-arg API: HANDLE (HKEY) + REGISTRY_SUBKEY
    auto db = MakeDb("TestRegSubkey", {ArgSpec{"HANDLE"}, ArgSpec{"REGISTRY_SUBKEY"}});
    auto prep = MakePreparer(db, hm, pm, pidm, ps, rs);
    const auto* sig = db.Find("TestRegSubkey");

    // 0x80000002 = HKEY_LOCAL_MACHINE (predefined, resolves to itself)
    auto ev = MakeEvent("TestRegSubkey", {
        (std::int64_t)0x80000002LL,
        std::wstring(L"SOFTWARE\\Test")
    });
    auto p = prep.Prepare(ev, *sig);

    // Sandbox redirects HKLM → HKCU
    EXPECT_EQ(reinterpret_cast<HKEY>(p.raw[0]), HKEY_CURRENT_USER);
    // Subkey is redirected under the sandbox root
    ASSERT_NE(p.raw[1], (DWORD_PTR)0);
    EXPECT_EQ(std::wstring(reinterpret_cast<const wchar_t*>(p.raw[1])),
              L"Software\\WinAPIReplaySandbox\\HKLM\\SOFTWARE\\Test");
}

// ── REGISTRY_SUBKEY_A arg ─────────────────────────────────────────────────

TEST(ArgPreparer, RegistrySubkeyAIsAnsi) {
    HandleMap hm; PointerMap pm; PidMap pidm;
    PathSandbox ps{L""};
    RegistrySandbox rs;  // disabled: no redirect, just ANSI conversion

    auto db = MakeDb("TestRegSubkeyA", {ArgSpec{"HANDLE"}, ArgSpec{"REGISTRY_SUBKEY_A"}});
    auto prep = MakePreparer(db, hm, pm, pidm, ps, rs);
    const auto* sig = db.Find("TestRegSubkeyA");

    auto ev = MakeEvent("TestRegSubkeyA", {
        (std::int64_t)0x80000002LL,
        std::wstring(L"SOFTWARE\\Test")
    });
    auto p = prep.Prepare(ev, *sig);
    ASSERT_NE(p.raw[1], (DWORD_PTR)0);
    // Buffer must be ANSI (char), not wide
    EXPECT_STREQ(reinterpret_cast<const char*>(p.raw[1]), "SOFTWARE\\Test");
}

// ── PathSandbox redirect ──────────────────────────────────────────────────

TEST(ArgPreparer, WStringPathRedirectedBySandbox) {
    HandleMap hm; PointerMap pm; PidMap pidm;
    PathSandbox ps{L"C:\\Sandbox"}; RegistrySandbox rs;
    // Must use category "file" so PathSandbox redirect is applied
    auto db = MakeDb("TestPath", {ArgSpec{"WSTRING"}}, "BOOL", "file");
    auto prep = MakePreparer(db, hm, pm, pidm, ps, rs);
    const auto* sig = db.Find("TestPath");

    auto ev = MakeEvent("TestPath", {std::wstring(L"C:\\Windows\\system32\\evil.dll")});
    auto p = prep.Prepare(ev, *sig);
    ASSERT_NE(p.raw[0], (DWORD_PTR)0);
    std::wstring result(reinterpret_cast<const wchar_t*>(p.raw[0]));
    EXPECT_EQ(result, L"C:\\Sandbox\\C_\\Windows\\system32\\evil.dll");
}

TEST(ArgPreparer, WStringNotRedirectedForNonFileCategory) {
    HandleMap hm; PointerMap pm; PidMap pidm;
    PathSandbox ps{L"C:\\Sandbox"}; RegistrySandbox rs;
    // category "process": PathSandbox must NOT be applied to WSTRING args
    auto db = MakeDb("TestPathNoRedir", {ArgSpec{"WSTRING"}}, "BOOL", "process");
    auto prep = MakePreparer(db, hm, pm, pidm, ps, rs);
    const auto* sig = db.Find("TestPathNoRedir");

    auto ev = MakeEvent("TestPathNoRedir", {std::wstring(L"C:\\Windows\\system32\\calc.exe")});
    auto p = prep.Prepare(ev, *sig);
    ASSERT_NE(p.raw[0], (DWORD_PTR)0);
    std::wstring result(reinterpret_cast<const wchar_t*>(p.raw[0]));
    EXPECT_EQ(result, L"C:\\Windows\\system32\\calc.exe");
}

// ── SandboxTransform recording ─────────────────────────────────────────────

TEST(ArgPreparer, PathTransformRecordedWhenSandboxActive) {
    HandleMap hm; PointerMap pm; PidMap pidm;
    PathSandbox ps{L"C:\\Sandbox"}; RegistrySandbox rs;
    auto db = MakeDb("CreateFileW", {ArgSpec{"WSTRING"}}, "HANDLE", "file");
    auto prep = MakePreparer(db, hm, pm, pidm, ps, rs);
    const auto* sig = db.Find("CreateFileW");

    auto ev = MakeEvent("CreateFileW", {std::wstring(L"C:\\Users\\victim\\evil.exe")});
    auto p = prep.Prepare(ev, *sig);

    ASSERT_EQ(p.transforms.size(), 1u);
    EXPECT_EQ(p.transforms[0].param_index, 0);
    EXPECT_EQ(p.transforms[0].original,  "C:\\Users\\victim\\evil.exe");
    EXPECT_EQ(p.transforms[0].rewritten, "C:\\Sandbox\\C_\\Users\\victim\\evil.exe");
}

TEST(ArgPreparer, PathTransformEmptyWhenSandboxDisabled) {
    HandleMap hm; PointerMap pm; PidMap pidm;
    PathSandbox ps{L""}; RegistrySandbox rs;
    auto db = MakeDb("CreateFileW", {ArgSpec{"WSTRING"}}, "HANDLE", "file");
    auto prep = MakePreparer(db, hm, pm, pidm, ps, rs);
    const auto* sig = db.Find("CreateFileW");

    auto ev = MakeEvent("CreateFileW", {std::wstring(L"C:\\Users\\victim\\evil.exe")});
    auto p = prep.Prepare(ev, *sig);

    EXPECT_TRUE(p.transforms.empty());
}

TEST(ArgPreparer, PathTransformEmptyForNonFileCategory) {
    HandleMap hm; PointerMap pm; PidMap pidm;
    PathSandbox ps{L"C:\\Sandbox"}; RegistrySandbox rs;
    auto db = MakeDb("TestProc", {ArgSpec{"WSTRING"}}, "HANDLE", "process");
    auto prep = MakePreparer(db, hm, pm, pidm, ps, rs);
    const auto* sig = db.Find("TestProc");

    auto ev = MakeEvent("TestProc", {std::wstring(L"C:\\Windows\\system32\\calc.exe")});
    auto p = prep.Prepare(ev, *sig);

    EXPECT_TRUE(p.transforms.empty());
}

TEST(ArgPreparer, MultiplePathArgsAllTransformed) {
    HandleMap hm; PointerMap pm; PidMap pidm;
    PathSandbox ps{L"C:\\Sandbox"}; RegistrySandbox rs;
    // MoveFileExW-like: two WSTRING args in file category
    auto db = MakeDb("MoveFileExW",
                     {ArgSpec{"WSTRING"}, ArgSpec{"WSTRING"}}, "BOOL", "file");
    auto prep = MakePreparer(db, hm, pm, pidm, ps, rs);
    const auto* sig = db.Find("MoveFileExW");

    auto ev = MakeEvent("MoveFileExW", {
        std::wstring(L"C:\\Users\\victim\\old.txt"),
        std::wstring(L"C:\\Users\\victim\\new.txt")
    });
    auto p = prep.Prepare(ev, *sig);

    ASSERT_EQ(p.transforms.size(), 2u);
    EXPECT_EQ(p.transforms[0].param_index, 0);
    EXPECT_EQ(p.transforms[0].original,  "C:\\Users\\victim\\old.txt");
    EXPECT_EQ(p.transforms[0].rewritten, "C:\\Sandbox\\C_\\Users\\victim\\old.txt");
    EXPECT_EQ(p.transforms[1].param_index, 1);
    EXPECT_EQ(p.transforms[1].original,  "C:\\Users\\victim\\new.txt");
    EXPECT_EQ(p.transforms[1].rewritten, "C:\\Sandbox\\C_\\Users\\victim\\new.txt");
}

TEST(ArgPreparer, RegistryTransformRecordedWhenSandboxActive) {
    HandleMap hm; PointerMap pm; PidMap pidm;
    PathSandbox ps{L""};
    RegistrySandbox rs;
    rs.Enable();

    auto db = MakeDb("RegCreateKeyExW",
                     {ArgSpec{"HANDLE"}, ArgSpec{"REGISTRY_SUBKEY"}}, "STATUS", "registry");
    auto prep = MakePreparer(db, hm, pm, pidm, ps, rs);
    const auto* sig = db.Find("RegCreateKeyExW");

    // 0x80000002 = HKEY_LOCAL_MACHINE (predefined)
    auto ev = MakeEvent("RegCreateKeyExW", {
        (std::int64_t)0x80000002LL,
        std::wstring(L"SOFTWARE\\Microsoft\\Windows")
    });
    auto p = prep.Prepare(ev, *sig);

    ASSERT_EQ(p.transforms.size(), 1u);
    EXPECT_EQ(p.transforms[0].param_index, 1);
    EXPECT_EQ(p.transforms[0].original,
              "HKLM\\SOFTWARE\\Microsoft\\Windows");
    EXPECT_EQ(p.transforms[0].rewritten,
              "HKCU\\Software\\WinAPIReplaySandbox\\HKLM\\SOFTWARE\\Microsoft\\Windows");
}

TEST(ArgPreparer, RegistryTransformEmptyWhenSandboxDisabled) {
    HandleMap hm; PointerMap pm; PidMap pidm;
    PathSandbox ps{L""};
    RegistrySandbox rs;  // NOT enabled

    auto db = MakeDb("RegCreateKeyExW",
                     {ArgSpec{"HANDLE"}, ArgSpec{"REGISTRY_SUBKEY"}}, "STATUS", "registry");
    auto prep = MakePreparer(db, hm, pm, pidm, ps, rs);
    const auto* sig = db.Find("RegCreateKeyExW");

    auto ev = MakeEvent("RegCreateKeyExW", {
        (std::int64_t)0x80000002LL,
        std::wstring(L"SOFTWARE\\Test")
    });
    auto p = prep.Prepare(ev, *sig);

    EXPECT_TRUE(p.transforms.empty());
}

TEST(ArgPreparer, RegistrySubkeyATransformRecorded) {
    HandleMap hm; PointerMap pm; PidMap pidm;
    PathSandbox ps{L""};
    RegistrySandbox rs;
    rs.Enable();

    auto db = MakeDb("RegCreateKeyExA",
                     {ArgSpec{"HANDLE"}, ArgSpec{"REGISTRY_SUBKEY_A"}}, "STATUS", "registry");
    auto prep = MakePreparer(db, hm, pm, pidm, ps, rs);
    const auto* sig = db.Find("RegCreateKeyExA");

    // HKCU = 0x80000001
    auto ev = MakeEvent("RegCreateKeyExA", {
        (std::int64_t)0x80000001LL,
        std::wstring(L"SOFTWARE\\AcmeCorp")
    });
    auto p = prep.Prepare(ev, *sig);

    ASSERT_EQ(p.transforms.size(), 1u);
    EXPECT_EQ(p.transforms[0].param_index, 1);
    EXPECT_EQ(p.transforms[0].original,  "HKCU\\SOFTWARE\\AcmeCorp");
    EXPECT_EQ(p.transforms[0].rewritten,
              "HKCU\\Software\\WinAPIReplaySandbox\\HKCU\\SOFTWARE\\AcmeCorp");
}
