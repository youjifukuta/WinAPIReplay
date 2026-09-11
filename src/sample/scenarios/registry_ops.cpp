#include <windows.h>
#include <cstdio>
#include "sample/log_helper.h"
#include "sample/scenarios.h"

int RunRegistryScenario() {
    printf("\n[SCENARIO] registry\n");
    int failures = 0;

    static const wchar_t* kKeyPath   = L"Software\\WinAPIReplayTest";
    static const wchar_t* kValueName = L"TestValue";
    static const wchar_t* kValueData = L"WinAPIReplaySample";

    // seq 1: RegCreateKeyExW
    HKEY hKey = nullptr;
    LONG rc = RegCreateKeyExW(HKEY_CURRENT_USER, kKeyPath, 0, nullptr,
                               REG_OPTION_NON_VOLATILE, KEY_READ | KEY_WRITE,
                               nullptr, &hKey, nullptr);
    if (rc != ERROR_SUCCESS) {
        LogCallErr("RegCreateKeyExW", "HKCU\\Software\\WinAPIReplayTest", (DWORD)rc);
        return ++failures;
    }
    LogCallOkOut("RegCreateKeyExW", "HKCU\\Software\\WinAPIReplayTest",
                  { { "phkResult", (DWORD_PTR)hKey } });

    // seq 2: RegSetValueExW
    DWORD dataSize = (DWORD)((wcslen(kValueData) + 1) * sizeof(wchar_t));
    rc = RegSetValueExW(hKey, kValueName, 0, REG_SZ,
                         reinterpret_cast<const BYTE*>(kValueData), dataSize);
    if (rc != ERROR_SUCCESS) {
        LogCallErr("RegSetValueExW", "TestValue=WinAPIReplaySample", (DWORD)rc);
        ++failures;
    } else {
        LogCallOk("RegSetValueExW", "TestValue=WinAPIReplaySample");
    }

    // seq 3: RegQueryValueExW
    wchar_t readBuf[256] = {};
    DWORD readSize = sizeof(readBuf);
    rc = RegQueryValueExW(hKey, kValueName, nullptr, nullptr,
                           reinterpret_cast<BYTE*>(readBuf), &readSize);
    if (rc != ERROR_SUCCESS) {
        LogCallErr("RegQueryValueExW", "TestValue", (DWORD)rc);
        ++failures;
    } else {
        LogCallOk("RegQueryValueExW", "TestValue");
    }

    // seq 4: RegDeleteValueW
    rc = RegDeleteValueW(hKey, kValueName);
    if (rc != ERROR_SUCCESS) {
        LogCallErr("RegDeleteValueW", "TestValue", (DWORD)rc);
        ++failures;
    } else {
        LogCallOk("RegDeleteValueW", "TestValue");
    }

    // seq 5: RegCloseKey
    rc = RegCloseKey(hKey);
    if (rc != ERROR_SUCCESS) {
        LogCallErr("RegCloseKey", "HKCU\\Software\\WinAPIReplayTest", (DWORD)rc);
        ++failures;
    } else {
        LogCallOk("RegCloseKey", "HKCU\\Software\\WinAPIReplayTest");
    }

    // seq 6: RegDeleteKeyW
    rc = RegDeleteKeyW(HKEY_CURRENT_USER, kKeyPath);
    if (rc != ERROR_SUCCESS) {
        LogCallErr("RegDeleteKeyW", "HKCU\\Software\\WinAPIReplayTest", (DWORD)rc);
        ++failures;
    } else {
        LogCallOk("RegDeleteKeyW", "HKCU\\Software\\WinAPIReplayTest");
    }

    printf("[RESULT] registry: %d/6 calls succeeded\n", 6 - failures);
    return failures;
}
