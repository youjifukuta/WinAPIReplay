#include <gtest/gtest.h>
#include "replay/registry_sandbox.h"

TEST(RegistrySandbox, DisabledByDefault) {
    RegistrySandbox sb;
    EXPECT_FALSE(sb.IsEnabled());
}

TEST(RegistrySandbox, EnabledAfterEnable) {
    RegistrySandbox sb;
    sb.Enable();
    EXPECT_TRUE(sb.IsEnabled());
}

TEST(RegistrySandbox, RedirectsHKLM) {
    RegistrySandbox sb;
    sb.Enable();
    auto [hk, sub] = sb.Redirect(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Test");
    EXPECT_EQ(hk, HKEY_CURRENT_USER);
    EXPECT_EQ(sub, std::wstring(L"Software\\WinAPIReplaySandbox\\HKLM\\SOFTWARE\\Test"));
}

TEST(RegistrySandbox, RedirectsHKCU) {
    RegistrySandbox sb;
    sb.Enable();
    auto [hk, sub] = sb.Redirect(HKEY_CURRENT_USER, L"SOFTWARE\\Test");
    EXPECT_EQ(hk, HKEY_CURRENT_USER);
    EXPECT_EQ(sub, std::wstring(L"Software\\WinAPIReplaySandbox\\HKCU\\SOFTWARE\\Test"));
}

TEST(RegistrySandbox, RedirectsHKCR) {
    RegistrySandbox sb;
    sb.Enable();
    auto [hk, sub] = sb.Redirect(HKEY_CLASSES_ROOT, L"*\\shell");
    EXPECT_EQ(hk, HKEY_CURRENT_USER);
    EXPECT_EQ(sub, std::wstring(L"Software\\WinAPIReplaySandbox\\HKCR\\*\\shell"));
}

TEST(RegistrySandbox, RedirectsHKU) {
    RegistrySandbox sb;
    sb.Enable();
    auto [hk, sub] = sb.Redirect(HKEY_USERS, L".DEFAULT\\key");
    EXPECT_EQ(hk, HKEY_CURRENT_USER);
    EXPECT_EQ(sub, std::wstring(L"Software\\WinAPIReplaySandbox\\HKU\\.DEFAULT\\key"));
}

TEST(RegistrySandbox, RedirectsEmptySubkey) {
    RegistrySandbox sb;
    sb.Enable();
    auto [hk, sub] = sb.Redirect(HKEY_LOCAL_MACHINE, L"");
    EXPECT_EQ(hk, HKEY_CURRENT_USER);
    EXPECT_EQ(sub, std::wstring(L"Software\\WinAPIReplaySandbox\\HKLM"));
}

TEST(RegistrySandbox, RedirectsHKCC) {
    RegistrySandbox sb;
    sb.Enable();
    auto [hk, sub] = sb.Redirect(HKEY_CURRENT_CONFIG, L"System\\CurrentControlSet");
    EXPECT_EQ(hk, HKEY_CURRENT_USER);
    EXPECT_EQ(sub, std::wstring(L"Software\\WinAPIReplaySandbox\\HKCC\\System\\CurrentControlSet"));
}
