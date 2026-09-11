#include "replay/executors/file_executor.h"
#include <string>

std::vector<std::string> FileExecutor::SupportedApis() const {
    return {
        "CreateFileW", "CreateFileA",
        "ReadFile", "WriteFile",
        "DeleteFileW", "DeleteFileA",
        "CloseHandle",
        "CopyFileW",
        "MoveFileExW",
        "CreateDirectoryW",
        "GetTempPathW", "GetTempFileNameW",
    };
}

DWORD_PTR FileExecutor::Execute(const LogEvent& event, const PreparedArgs& p) {
    const auto& n = event.api_name;

    if (n == "CreateFileW") {
        // Parent directory pre-created by ApiExecutor::PreInit; single CreateFileW call.
        return (DWORD_PTR)CreateFileW(
            (LPCWSTR)p.raw[0], (DWORD)p.raw[1], (DWORD)p.raw[2],
            (LPSECURITY_ATTRIBUTES)p.raw[3], (DWORD)p.raw[4],
            (DWORD)p.raw[5], (HANDLE)p.raw[6]);
    }
    if (n == "CreateFileA") {
        return (DWORD_PTR)CreateFileA(
            (LPCSTR)p.raw[0], (DWORD)p.raw[1], (DWORD)p.raw[2],
            (LPSECURITY_ATTRIBUTES)p.raw[3], (DWORD)p.raw[4],
            (DWORD)p.raw[5], (HANDLE)p.raw[6]);
    }
    if (n == "ReadFile") {
        DWORD read = 0;
        return (DWORD_PTR)ReadFile((HANDLE)p.raw[0], (LPVOID)p.raw[1],
                                   (DWORD)p.raw[2], &read, nullptr);
    }
    if (n == "WriteFile") {
        DWORD written = 0;
        return (DWORD_PTR)WriteFile((HANDLE)p.raw[0], (LPCVOID)p.raw[1],
                                    (DWORD)p.raw[2], &written, nullptr);
    }
    if (n == "DeleteFileW")  return (DWORD_PTR)DeleteFileW((LPCWSTR)p.raw[0]);
    if (n == "DeleteFileA")  return (DWORD_PTR)DeleteFileA((LPCSTR)p.raw[0]);

    if (n == "CloseHandle") {
        HANDLE h = (HANDLE)p.raw[0];
        // Unmapped/null handle: nothing to close, report success
        if (!h || h == INVALID_HANDLE_VALUE) return TRUE;
        return (DWORD_PTR)CloseHandle(h);
    }

    if (n == "CopyFileW")
        return (DWORD_PTR)CopyFileW((LPCWSTR)p.raw[0], (LPCWSTR)p.raw[1], (BOOL)p.raw[2]);
    if (n == "MoveFileExW")
        return (DWORD_PTR)MoveFileExW((LPCWSTR)p.raw[0], (LPCWSTR)p.raw[1], (DWORD)p.raw[2]);

    if (n == "CreateDirectoryW") {
        BOOL r = CreateDirectoryW((LPCWSTR)p.raw[0], nullptr);
        // Already exists is success: the directory state matches what malware expected
        if (!r && GetLastError() == ERROR_ALREADY_EXISTS) r = TRUE;
        return (DWORD_PTR)r;
    }
    if (n == "GetTempPathW") {
        wchar_t buf[MAX_PATH] = {};
        return (DWORD_PTR)GetTempPathW(MAX_PATH, buf);
    }
    if (n == "GetTempFileNameW") {
        wchar_t buf[MAX_PATH] = {};
        return (DWORD_PTR)GetTempFileNameW((LPCWSTR)p.raw[0], (LPCWSTR)p.raw[1],
                                           (UINT)p.raw[2], buf);
    }
    return 0;
}
