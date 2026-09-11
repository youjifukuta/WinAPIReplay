#include <windows.h>
#include <cstdio>
#include "sample/log_helper.h"
#include "sample/scenarios.h"

int RunFileScenario() {
    printf("\n[SCENARIO] file\n");
    int failures = 0;

    // C:\Temp を確保（ログ対象外）
    CreateDirectoryW(L"C:\\Temp", nullptr);

    static const wchar_t* kPath    = L"C:\\Temp\\winapi_sample.txt";
    static const char*    kData    = "WinAPIReplaySample\n";
    static const DWORD    kDataLen = 19;

    // seq 1: CreateFileW (GENERIC_WRITE)
    HANDLE hWrite = CreateFileW(kPath, GENERIC_WRITE, 0, nullptr,
                                 CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hWrite == INVALID_HANDLE_VALUE) {
        LogCallErr("CreateFileW", "C:\\Temp\\winapi_sample.txt", GetLastError());
        return ++failures;
    }
    LogCallOk("CreateFileW", "C:\\Temp\\winapi_sample.txt");

    // seq 2: WriteFile
    DWORD written = 0;
    if (!WriteFile(hWrite, kData, kDataLen, &written, nullptr)) {
        LogCallErr("WriteFile", "written=0", GetLastError());
        ++failures;
    } else {
        char detail[64];
        sprintf_s(detail, "written=%lu", written);
        LogCallOk("WriteFile", detail);
    }

    // seq 3: CloseHandle（書き込みハンドル）
    {
        char detail[64];
        sprintf_s(detail, "handle=0x%08llX", (unsigned long long)hWrite);
        if (!CloseHandle(hWrite)) {
            LogCallErr("CloseHandle", detail, GetLastError()); ++failures;
        } else {
            LogCallOk("CloseHandle", detail);
        }
    }

    // seq 4: CreateFileW (GENERIC_READ)
    HANDLE hRead = CreateFileW(kPath, GENERIC_READ, 0, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hRead == INVALID_HANDLE_VALUE) {
        LogCallErr("CreateFileW", "C:\\Temp\\winapi_sample.txt", GetLastError());
        return ++failures;
    }
    LogCallOk("CreateFileW", "C:\\Temp\\winapi_sample.txt");

    // seq 5: ReadFile
    char buf[64] = {};
    DWORD bytesRead = 0;
    if (!ReadFile(hRead, buf, kDataLen, &bytesRead, nullptr)) {
        LogCallErr("ReadFile", "read=0", GetLastError());
        ++failures;
    } else {
        char detail[64];
        sprintf_s(detail, "read=%lu", bytesRead);
        LogCallOk("ReadFile", detail);
    }

    // seq 6: CloseHandle（読み取りハンドル）
    {
        char detail[64];
        sprintf_s(detail, "handle=0x%08llX", (unsigned long long)hRead);
        if (!CloseHandle(hRead)) {
            LogCallErr("CloseHandle", detail, GetLastError()); ++failures;
        } else {
            LogCallOk("CloseHandle", detail);
        }
    }

    // seq 7: DeleteFileW
    if (!DeleteFileW(kPath)) {
        LogCallErr("DeleteFileW", "C:\\Temp\\winapi_sample.txt", GetLastError());
        ++failures;
    } else {
        LogCallOk("DeleteFileW", "C:\\Temp\\winapi_sample.txt");
    }

    printf("[RESULT] file: %d/7 calls succeeded\n", 7 - failures);
    return failures;
}
