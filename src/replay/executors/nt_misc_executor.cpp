#include "replay/executors/nt_misc_executor.h"
#include "replay/utils.h"
#include <windows.h>
#include <shlwapi.h>
#include <pathcch.h>
#include <ntsecapi.h>
#include <ole2.h>
#include <shellapi.h>

// ── Helpers ───────────────────────────────────────────────────────────────────

DWORD_PTR NtMiscExecutor::ReadHexArg(const LogEvent& event, int idx) {
    if (idx >= (int)event.args.size()) return 0;
    if (auto* ws = std::get_if<std::wstring>(&event.args[idx])) {
        try { return HexToPtr(WideToUtf8(*ws)); } catch (...) { return 0; }
    }
    if (auto* iv = std::get_if<std::int64_t>(&event.args[idx]))
        return (DWORD_PTR)*iv;
    return 0;
}

std::wstring NtMiscExecutor::ReadStrArg(const LogEvent& event, int idx) {
    if (idx >= (int)event.args.size()) return {};
    if (auto* ws = std::get_if<std::wstring>(&event.args[idx])) return *ws;
    return {};
}

SIZE_T NtMiscExecutor::ReadSizeArg(const LogEvent& event, int idx) {
    return (SIZE_T)ReadHexArg(event, idx);
}

// ── SupportedApis ─────────────────────────────────────────────────────────────

std::vector<std::string> NtMiscExecutor::SupportedApis() const {
    return {
        // Transaction / thread pool (no-op)
        "RtlSetCurrentTransaction", "NtSetInformationTransaction",
        "TpAllocWork", "TpPostWork", "TpReleaseWork",

        // Exception handlers (safe stubs)
        "RtlAddVectoredExceptionHandler",    "RtlRemoveVectoredExceptionHandler",
        "RtlAddVectoredContinueHandler",     "RtlRemoveVectoredContinueHandler",
        "AddVectoredExceptionHandler",       "RemoveVectoredExceptionHandler",
        "SetUnhandledExceptionFilter",

        // Process / thread info (no-op / zero-fill)
        "NtQueryInformationProcess", "ZwQueryInformationProcess",
        "NtSetInformationProcess",   "ZwSetInformationProcess",
        "NtQueryInformationThread",  "ZwQueryInformationThread",
        "NtSetInformationThread",    "ZwSetInformationThread",
        "NtGetContextThread",        "NtSetContextThread",
        "NtSuspendThread",
        "NtResumeThread",            "ZwResumeThread",
        "NtCreateThreadEx",
        "NtCreateUserProcess",       "ZwCreateUserProcess",

        // Token (delegated from old kLayer2Blocked)
        "NtOpenProcessToken",     "NtOpenProcessTokenEx",
        "NtOpenThreadToken",      "NtOpenThreadTokenEx",
        "NtQueryInformationToken","NtSetInformationToken",
        "NtAdjustPrivilegesToken",
        "OpenThreadToken",
        "LookupPrivilegeValueW",  "LookupPrivilegeValueA",
        "LookupPrivilegeNameW",   "LookupPrivilegeNameA",
        "AdjustTokenGroups",
        "LsaOpenPolicy",
        "NtOpenProcess",          "ZwOpenProcess",
        "NtOpenThread",           "ZwOpenThread",

        // COM
        "CoCreateInstance", "CoGetClassObject",
        "CoInitialize", "CoInitializeEx", "CoUninitialize",
        "OleInitialize", "OleUninitialize",

        // Shell / UI
        "ShellExecuteExW", "ShellExecuteExA",
        "UpdateProcThreadAttribute",
        "SystemParametersInfoW", "SystemParametersInfoA",

        // Find-file (sandbox)
        "FindFirstFileExW", "FindFirstFileW",
        "FindNextFileW",    "FindNextFileA",

        // Path combining / canonicalization
        "PathCombineW", "PathCombineA",
        "PathCchCombineEx", "PathCchCombineExW",
        "PathCchCombine",   "PathCchCombineW",
        "PathAppendW",      "PathAppendA",
        "PathCanonicalizeW","PathCanonicalizeA",
        "PathAddBackslashW","PathAddBackslashA",
        "PathRemoveFileSpecW","PathRemoveFileSpecA",
        "PathAllocCombine", "PathAllocCombineW",
        "UrlCanonicalizeW", "UrlCanonicalizeA",
        "UrlCombineW",      "UrlCombineA",
        "RtlDosPathNameToNtPathName_U",
        "RtlDosPathNameToRelativeName_U",

        // NT file info / IO (lightweight)
        "NtQueryAttributesFile",     "ZwQueryAttributesFile",
        "NtQueryFullAttributesFile",
        "NtFlushBuffersFile",        "NtCancelIoFile",
        "NtDeviceIoControlFile",     "NtFsControlFile",
        "NtLockFile",                "NtUnlockFile",
    };
}

// ── Execute ───────────────────────────────────────────────────────────────────

DWORD_PTR NtMiscExecutor::Execute(const LogEvent& event, const PreparedArgs& p) {
    const auto& n = event.api_name;

    // ── Transaction / thread pool ─────────────────────────────────────────────
    if (n == "RtlSetCurrentTransaction" ||
        n == "NtSetInformationTransaction" ||
        n == "TpAllocWork" || n == "TpPostWork" || n == "TpReleaseWork")
        return 0;  // STATUS_SUCCESS / no-op

    // ── Vectored exception handlers ────────────────────────────────────────────
    if (n == "RtlAddVectoredExceptionHandler" ||
        n == "RtlAddVectoredContinueHandler"  ||
        n == "AddVectoredExceptionHandler")
        return 1;  // non-NULL = success handle

    if (n == "RtlRemoveVectoredExceptionHandler" ||
        n == "RtlRemoveVectoredContinueHandler"  ||
        n == "RemoveVectoredExceptionHandler")
        return (DWORD_PTR)TRUE;

    if (n == "SetUnhandledExceptionFilter")
        return 0;  // returns previous filter (NULL)

    // ── NtQueryInformationProcess / Thread ─────────────────────────────────────
    if (n == "NtQueryInformationProcess" || n == "ZwQueryInformationProcess" ||
        n == "NtQueryInformationThread"  || n == "ZwQueryInformationThread")
        return 0;  // STATUS_SUCCESS, zero-fill buffer (not used by downstream)

    // ── NtSetInformation* (no-op) ──────────────────────────────────────────────
    if (n == "NtSetInformationProcess" || n == "ZwSetInformationProcess" ||
        n == "NtSetInformationThread"  || n == "ZwSetInformationThread")
        return 0;

    // ── Thread context / suspend / resume ──────────────────────────────────────
    if (n == "NtGetContextThread" || n == "NtSetContextThread" ||
        n == "NtSuspendThread")
        return 0;

    if (n == "NtResumeThread" || n == "ZwResumeThread") {
        DWORD_PTR orig_h = ReadHexArg(event, 0);
        HANDLE h = (HANDLE)handle_map_.Resolve(orig_h);
        // Only resume if we have a valid mapped thread handle
        if (h && h != (HANDLE)orig_h && h != GetCurrentThread())
            ResumeThread(h);
        return 0;
    }

    // ── NtCreateThreadEx / NtCreateUserProcess (no-spawn) ─────────────────────
    if (n == "NtCreateThreadEx" ||
        n == "NtCreateUserProcess" || n == "ZwCreateUserProcess") {
        // Provide a dummy handle so downstream NtClose doesn't fail on unmapped handle
        DWORD_PTR orig_h = ReadHexArg(event, 0);
        if (orig_h != 0 && !handle_map_.HasMapping(orig_h)) {
            HANDLE dummy = nullptr;
            DuplicateHandle(GetCurrentProcess(), GetCurrentThread(),
                            GetCurrentProcess(), &dummy, 0, FALSE, DUPLICATE_SAME_ACCESS);
            if (dummy) handle_map_.Register(orig_h, (DWORD_PTR)dummy);
        }
        return 0;
    }

    // ── NtOpenProcess / NtOpenThread ────────────────────────────────────────────
    if (n == "NtOpenProcess" || n == "ZwOpenProcess") {
        DWORD_PTR orig_h = ReadHexArg(event, 0);
        DWORD_PTR pid_v  = ReadHexArg(event, 3);

        HANDLE h = nullptr;
        if (pid_v != 0) {
            h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)pid_v);
            if (!h) h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid_v);
        }
        if (!h) h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                FALSE, GetCurrentProcessId());
        if (h && orig_h) handle_map_.Register(orig_h, (DWORD_PTR)h);
        return 0;
    }

    if (n == "NtOpenThread" || n == "ZwOpenThread") {
        DWORD_PTR orig_h = ReadHexArg(event, 0);
        DWORD_PTR tid_v  = ReadHexArg(event, 4);

        HANDLE h = nullptr;
        if (tid_v != 0) h = OpenThread(THREAD_ALL_ACCESS, FALSE, (DWORD)tid_v);
        if (!h) {
            DuplicateHandle(GetCurrentProcess(), GetCurrentThread(),
                            GetCurrentProcess(), &h, 0, FALSE, DUPLICATE_SAME_ACCESS);
        }
        if (h && orig_h) handle_map_.Register(orig_h, (DWORD_PTR)h);
        return 0;
    }

    // ── Token APIs ─────────────────────────────────────────────────────────────
    if (n == "NtOpenProcessToken" || n == "NtOpenProcessTokenEx") {
        // output is last WSTRING arg (args[2] or args[3])
        int out_idx = (n == "NtOpenProcessTokenEx") ? 3 : 2;
        DWORD_PTR orig_tok = ReadHexArg(event, out_idx);

        HANDLE proc_h_orig = (HANDLE)ReadHexArg(event, 0);
        HANDLE proc_h = (HANDLE)handle_map_.Resolve((DWORD_PTR)proc_h_orig);
        if (!proc_h) proc_h = GetCurrentProcess();

        HANDLE tok = nullptr;
        if (!OpenProcessToken(proc_h, TOKEN_ALL_ACCESS, &tok))
            OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &tok);
        if (tok && orig_tok) handle_map_.Register(orig_tok, (DWORD_PTR)tok);
        return 0;
    }

    if (n == "NtOpenThreadToken" || n == "NtOpenThreadTokenEx") {
        int out_idx = (n == "NtOpenThreadTokenEx") ? 4 : 3;
        DWORD_PTR orig_tok = ReadHexArg(event, out_idx);

        HANDLE tok = nullptr;
        OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &tok);
        if (tok && orig_tok) handle_map_.Register(orig_tok, (DWORD_PTR)tok);
        return 0;
    }

    if (n == "OpenThreadToken") {
        // Win32 variant; out handle is at args[3] (PTR_OUT in sig_db → PreparedArgs)
        // but sig_db specifies PTR_OUT so arg_preparer fills p.raw[3].
        // We also check event.args for safety.
        DWORD_PTR orig_tok = ReadHexArg(event, 3);
        HANDLE tok = nullptr;
        OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &tok);
        if (tok && orig_tok) handle_map_.Register(orig_tok, (DWORD_PTR)tok);
        return (DWORD_PTR)TRUE;
    }

    if (n == "NtQueryInformationToken" || n == "NtSetInformationToken" ||
        n == "NtAdjustPrivilegesToken")
        return 0;

    if (n == "LookupPrivilegeValueW") {
        std::wstring priv = ReadStrArg(event, 1);
        LUID luid{};
        if (!priv.empty()) LookupPrivilegeValueW(nullptr, priv.c_str(), &luid);
        return (DWORD_PTR)TRUE;
    }
    if (n == "LookupPrivilegeValueA") {
        std::wstring priv_w = ReadStrArg(event, 1);
        std::string priv_a = WideToUtf8(priv_w);
        LUID luid{};
        if (!priv_a.empty()) LookupPrivilegeValueA(nullptr, priv_a.c_str(), &luid);
        return (DWORD_PTR)TRUE;
    }
    if (n == "LookupPrivilegeNameW" || n == "LookupPrivilegeNameA")
        return (DWORD_PTR)TRUE;

    if (n == "AdjustTokenGroups")
        return (DWORD_PTR)TRUE;

    if (n == "LsaOpenPolicy") {
        // Output handle: attempt args[3] then args[1]
        DWORD_PTR orig_h = ReadHexArg(event, 3);
        if (orig_h == 0) orig_h = ReadHexArg(event, 1);

        LSA_OBJECT_ATTRIBUTES attrs{};
        attrs.Length = sizeof(attrs);
        LSA_HANDLE policy = nullptr;
        LsaOpenPolicy(nullptr, &attrs, POLICY_READ, &policy);
        if (policy && orig_h) handle_map_.Register(orig_h, (DWORD_PTR)policy);
        return 0;
    }

    // ── COM ────────────────────────────────────────────────────────────────────
    if (n == "CoCreateInstance" || n == "CoGetClassObject") {
        // Attempt to parse the CLSID/IID from the WinMET-encoded string args and
        // call the real COM API.  Many malware samples use standard Windows CLSIDs
        // (IExplorer, IShellItem, WScript.Shell, etc.) that succeed on the replay VM.
        std::wstring clsid_str = ReadStrArg(event, 0);
        std::wstring iid_str   = ReadStrArg(event, 3);
        CLSID clsid{}; IID iid{};
        bool have_clsid = (!clsid_str.empty() &&
                           SUCCEEDED(CLSIDFromString(clsid_str.c_str(), &clsid)));
        bool have_iid   = (!iid_str.empty() &&
                           SUCCEEDED(IIDFromString(iid_str.c_str(), &iid)));
        if (have_clsid && have_iid) {
            DWORD ctx = (event.args.size() > 2) ? (DWORD)ReadSizeArg(event, 2) : 0;
            if (!ctx) ctx = CLSCTX_INPROC_SERVER;
            void* pv = nullptr;
            HRESULT hr;
            if (n == "CoCreateInstance") {
                hr = CoCreateInstance(clsid, nullptr, ctx, iid, &pv);
            } else {
                hr = CoGetClassObject(clsid, ctx, nullptr, iid, &pv);
            }
            if (pv) {
                reinterpret_cast<IUnknown*>(pv)->Release();
                pv = nullptr;
            }
            return (DWORD_PTR)hr;
        }
        return 0x80040154;  // REGDB_E_CLASSNOTREG (fallback when CLSID/IID not parseable)
    }

    if (n == "CoInitialize" || n == "OleInitialize") {
        CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        return 0;  // S_OK
    }
    if (n == "CoInitializeEx") {
        DWORD dwCoInit = (DWORD)ReadSizeArg(event, 1);
        if (dwCoInit == 0) dwCoInit = COINIT_MULTITHREADED;
        CoInitializeEx(nullptr, dwCoInit);
        return 0;
    }
    if (n == "CoUninitialize" || n == "OleUninitialize")
        return 0;  // NOP — avoid cleanup ordering issues

    // ── Shell / UI ─────────────────────────────────────────────────────────────
    if (n == "ShellExecuteExW" || n == "ShellExecuteExA")
        return (DWORD_PTR)TRUE;  // block spawning, report success

    if (n == "UpdateProcThreadAttribute")
        return (DWORD_PTR)TRUE;

    // SystemParametersInfo: always return TRUE without calling the real API.
    // The even/odd parity heuristic for GET vs. SET is inconsistent across SPI ranges
    // (e.g. SPI_GETBEEP=0x0001 is odd=GET, SPI_SETBEEP=0x0002 is even=SET, contrary to
    // the "even=GET" assumption for the 0x000A+ range).  Calling a SET action with a 4-byte
    // BOOL pvParam buffer also corrupts the stack for actions returning wider structs
    // (e.g. SPI_GETWORKAREA fills a RECT=16 bytes).  No-op is safe and accurate enough.
    if (n == "SystemParametersInfoW" || n == "SystemParametersInfoA")
        return (DWORD_PTR)TRUE;

    // ── FindFirstFile / FindNextFile (sandbox) ─────────────────────────────────
    if (n == "FindFirstFileExW" || n == "FindFirstFileW") {
        std::wstring path = ReadStrArg(event, 0);

        std::wstring sb_path;
        if (!path.empty() && path_sandbox_.IsEnabled())
            sb_path = path_sandbox_.Redirect(path);
        if (sb_path.empty()) sb_path = L"*";  // fallback

        WIN32_FIND_DATAW fd{};
        HANDLE h = FindFirstFileExW(sb_path.c_str(), FindExInfoStandard, &fd,
                                     FindExSearchNameMatch, nullptr, 0);
        // For WinMET logs the return value IS the find handle; register it
        if (h != INVALID_HANDLE_VALUE) {
            // The handle value to use as key depends on log format:
            // In WinMET return_val is the HANDLE, handled by ApiExecutor.UpdateMaps
            // for sig_db return_type=HANDLE. Nothing extra needed here.
        }
        return (h != INVALID_HANDLE_VALUE) ? (DWORD_PTR)h : (DWORD_PTR)INVALID_HANDLE_VALUE;
    }

    if (n == "FindNextFileW" || n == "FindNextFileA") {
        // WinMET logs: args[0]=found filename (output), args[1]=hFindFile (handle)
        DWORD_PTR orig_h = ReadHexArg(event, 1);
        if (orig_h == 0) orig_h = ReadHexArg(event, 0);  // fallback for other log formats
        HANDLE h = (HANDLE)handle_map_.Resolve(orig_h);
        if (h && h != INVALID_HANDLE_VALUE) {
            WIN32_FIND_DATAW fd{};
            BOOL r = FindNextFileW(h, &fd);
            return (DWORD_PTR)r;
        }
        return (DWORD_PTR)FALSE;
    }

    // ── Path APIs ──────────────────────────────────────────────────────────────
    if (n == "PathCombineW") {
        std::wstring dir  = ReadStrArg(event, 1);
        std::wstring file = ReadStrArg(event, 2);
        wchar_t result[MAX_PATH]{};
        PathCombineW(result, dir.c_str(), file.c_str());
        return (DWORD_PTR)TRUE;
    }
    if (n == "PathCombineA") {
        std::wstring dir_w  = ReadStrArg(event, 1);
        std::wstring file_w = ReadStrArg(event, 2);
        std::string dir_a  = WideToUtf8(dir_w);
        std::string file_a = WideToUtf8(file_w);
        char result[MAX_PATH]{};
        PathCombineA(result, dir_a.c_str(), file_a.c_str());
        return (DWORD_PTR)TRUE;
    }
    if (n == "PathCchCombineEx" || n == "PathCchCombineExW" ||
        n == "PathCchCombine"   || n == "PathCchCombineW") {
        std::wstring dir  = ReadStrArg(event, 2);
        std::wstring file = ReadStrArg(event, 3);
        wchar_t result[MAX_PATH]{};
        PathCchCombineEx(result, MAX_PATH, dir.c_str(), file.c_str(), 0);
        return 0;  // S_OK
    }
    if (n == "PathAppendW") {
        std::wstring path = ReadStrArg(event, 0);
        std::wstring more = ReadStrArg(event, 1);
        wchar_t buf[MAX_PATH]{};
        wcsncpy_s(buf, path.c_str(), MAX_PATH - 1);
        PathAppendW(buf, more.c_str());
        return (DWORD_PTR)TRUE;
    }
    if (n == "PathAppendA") {
        return (DWORD_PTR)TRUE;
    }
    if (n == "PathCanonicalizeW") {
        std::wstring src = ReadStrArg(event, 1);
        wchar_t result[MAX_PATH]{};
        PathCanonicalizeW(result, src.c_str());
        return (DWORD_PTR)TRUE;
    }
    if (n == "PathCanonicalizeA") {
        return (DWORD_PTR)TRUE;
    }
    if (n == "PathAddBackslashW") {
        std::wstring path = ReadStrArg(event, 0);
        wchar_t buf[MAX_PATH]{};
        wcsncpy_s(buf, path.c_str(), MAX_PATH - 1);
        PathAddBackslashW(buf);
        return 1;  // non-NULL ptr = success
    }
    if (n == "PathAddBackslashA") { return 1; }
    if (n == "PathRemoveFileSpecW") {
        std::wstring path = ReadStrArg(event, 0);
        wchar_t buf[MAX_PATH]{};
        wcsncpy_s(buf, path.c_str(), MAX_PATH - 1);
        PathRemoveFileSpecW(buf);
        return (DWORD_PTR)TRUE;
    }
    if (n == "PathRemoveFileSpecA") { return (DWORD_PTR)TRUE; }
    if (n == "PathAllocCombine" || n == "PathAllocCombineW") {
        // Cannot safely return an allocated path pointer into caller memory.
        // Return S_OK; callers that free the pointer will get a benign NOP.
        return 0;  // S_OK
    }
    if (n == "UrlCanonicalizeW") {
        std::wstring url = ReadStrArg(event, 0);
        wchar_t result[2048]{};
        DWORD sz = 2048;
        UrlCanonicalizeW(url.c_str(), result, &sz, 0);
        return 0;  // S_OK
    }
    if (n == "UrlCanonicalizeA" || n == "UrlCombineW" || n == "UrlCombineA")
        return 0;

    if (n == "RtlDosPathNameToNtPathName_U" ||
        n == "RtlDosPathNameToRelativeName_U")
        return (DWORD_PTR)TRUE;

    // ── NT file attributes / IO (lightweight) ──────────────────────────────────
    if (n == "NtQueryAttributesFile"     ||
        n == "ZwQueryAttributesFile"     ||
        n == "NtQueryFullAttributesFile") {
        std::wstring path = ReadStrArg(event, 0);
        WIN32_FILE_ATTRIBUTE_DATA fd{};
        bool found = false;

        if (!path.empty()) {
            auto strip = [&](const wchar_t* pfx) {
                size_t plen = wcslen(pfx);
                if (path.size() > plen && _wcsnicmp(path.c_str(), pfx, plen) == 0)
                    path = path.substr(plen);
            };
            strip(L"\\??\\"); strip(L"\\?\\");
            if (!path.empty() && path[0] != L'\\') {
                std::wstring sb = path_sandbox_.IsEnabled()
                                ? path_sandbox_.Redirect(path) : path;
                found = (GetFileAttributesExW(sb.c_str(), GetFileExInfoStandard, &fd) != FALSE);
                // Fall back to the real path for files that exist on the host but not in the
                // sandbox (e.g. C:\Windows\System32\kernel32.dll, C:\temp).  The original
                // malware saw these files as present, so we should too.
                if (!found && path_sandbox_.IsEnabled() && sb != path)
                    found = (GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fd) != FALSE);
            }
        }

        if (!found) return 0xC0000034;  // STATUS_OBJECT_NAME_NOT_FOUND

        // Fill FILE_BASIC_INFORMATION (or FILE_NETWORK_OPEN_INFORMATION for Full variant)
        // if the caller allocated an output buffer (arg[1] as DATA_OUT in sig_db).
        // The struct layout for FILE_BASIC_INFORMATION:
        //   LARGE_INTEGER CreationTime, LastAccessTime, LastWriteTime, ChangeTime;
        //   ULONG         FileAttributes;  (total 40 bytes)
        if (p.raw.size() > 1 && p.raw[1] != 0) {
            struct FBInfo {
                LARGE_INTEGER CreationTime, LastAccessTime, LastWriteTime, ChangeTime;
                ULONG         FileAttributes;
            };
            auto* fbi = reinterpret_cast<FBInfo*>(p.raw[1]);
            fbi->FileAttributes = fd.dwFileAttributes;
            auto conv = [](FILETIME ft) -> LARGE_INTEGER {
                LARGE_INTEGER li; li.LowPart = ft.dwLowDateTime; li.HighPart = (LONG)ft.dwHighDateTime; return li;
            };
            fbi->CreationTime   = conv(fd.ftCreationTime);
            fbi->LastAccessTime = conv(fd.ftLastAccessTime);
            fbi->LastWriteTime  = conv(fd.ftLastWriteTime);
            fbi->ChangeTime     = conv(fd.ftLastWriteTime);
        }
        return 0;  // STATUS_SUCCESS
    }

    if (n == "NtFlushBuffersFile") {
        DWORD_PTR orig_h = ReadHexArg(event, 0);
        HANDLE h = (HANDLE)handle_map_.Resolve(orig_h);
        if (h && h != (HANDLE)orig_h) FlushFileBuffers(h);
        return 0;
    }

    if (n == "NtCancelIoFile"        ||
        n == "NtDeviceIoControlFile" ||
        n == "NtFsControlFile"       ||
        n == "NtLockFile"            ||
        n == "NtUnlockFile")
        return 0;

    return 0;
}
