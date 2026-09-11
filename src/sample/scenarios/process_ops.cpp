#include <windows.h>
#include <cstdio>
#include "sample/log_helper.h"
#include "sample/scenarios.h"

int RunProcessScenario() {
    printf("\n[SCENARIO] process\n");
    int failures = 0;

    // cmd.exe のパスを GetSystemDirectoryW で動的取得
    wchar_t sysDir[MAX_PATH] = {};
    GetSystemDirectoryW(sysDir, MAX_PATH);
    wchar_t cmdPath[MAX_PATH] = {};
    swprintf_s(cmdPath, L"%s\\cmd.exe", sysDir);
    wchar_t cmdLine[MAX_PATH + 64] = {};
    swprintf_s(cmdLine, L"\"%s\" /c echo WinAPIReplaySample", cmdPath);

    // seq 1: CreateProcessW
    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};
    BOOL created = CreateProcessW(
        cmdPath, cmdLine, nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    if (!created) {
        LogCallErr("CreateProcessW", "cmd.exe /c echo WinAPIReplaySample", GetLastError());
        return ++failures;
    }
    LogCallOkOut("CreateProcessW", "cmd.exe /c echo WinAPIReplaySample",
                  { { "hProcess", (DWORD_PTR)pi.hProcess },
                    { "hThread",  (DWORD_PTR)pi.hThread  } });

    // seq 2: OpenProcess
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
    if (!hProc) {
        LogCallErr("OpenProcess", "PROCESS_ALL_ACCESS", GetLastError());
        ++failures;
    } else {
        char detail[64];
        sprintf_s(detail, "PROCESS_ALL_ACCESS pid=%lu", pi.dwProcessId);
        LogCallOk("OpenProcess", detail);
    }

    // seq 3: WaitForSingleObject（pi.hProcess）
    DWORD waitRet = WaitForSingleObject(pi.hProcess, 5000);
    if (waitRet == WAIT_FAILED) {
        LogCallErr("WaitForSingleObject", "pi.hProcess", GetLastError());
        ++failures;
    } else {
        LogCallOk("WaitForSingleObject",
                   waitRet == WAIT_OBJECT_0 ? "WAIT_OBJECT_0" : "WAIT_TIMEOUT");
    }

    // seq 4: CloseHandle（OpenProcess ハンドル）
    if (hProc) {
        char detail[64];
        sprintf_s(detail, "handle=0x%08llX", (unsigned long long)hProc);
        if (!CloseHandle(hProc)) {
            LogCallErr("CloseHandle", detail, GetLastError()); ++failures;
        } else {
            LogCallOk("CloseHandle", detail);
        }
    } else {
        ++failures; // OpenProcess 失敗によりスキップ
    }

    // seq 5: CloseHandle（pi.hProcess）
    {
        char detail[64];
        sprintf_s(detail, "handle=0x%08llX", (unsigned long long)pi.hProcess);
        if (!CloseHandle(pi.hProcess)) {
            LogCallErr("CloseHandle", detail, GetLastError()); ++failures;
        } else {
            LogCallOk("CloseHandle", detail);
        }
    }

    // seq 6: CloseHandle（pi.hThread）
    {
        char detail[64];
        sprintf_s(detail, "handle=0x%08llX", (unsigned long long)pi.hThread);
        if (!CloseHandle(pi.hThread)) {
            LogCallErr("CloseHandle", detail, GetLastError()); ++failures;
        } else {
            LogCallOk("CloseHandle", detail);
        }
    }

    printf("[RESULT] process: %d/6 calls succeeded\n", 6 - failures);
    return failures;
}
