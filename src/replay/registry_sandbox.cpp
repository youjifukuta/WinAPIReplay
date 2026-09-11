#include "replay/registry_sandbox.h"
#include <stdexcept>

std::wstring RegistrySandbox::RootKeyName(HKEY root) {
    // Compare as ULONG_PTR to handle both 64-bit sign-extended form (0xFFFFFFFF8000000X,
    // from 64-bit logs) and 32-bit truncated form (0x8000000X, from 32-bit logs).
    ULONG_PTR v = (ULONG_PTR)root;
    if (v == (ULONG_PTR)HKEY_CLASSES_ROOT   || v == 0x80000000UL) return L"HKCR";
    if (v == (ULONG_PTR)HKEY_CURRENT_USER   || v == 0x80000001UL) return L"HKCU";
    if (v == (ULONG_PTR)HKEY_LOCAL_MACHINE  || v == 0x80000002UL) return L"HKLM";
    if (v == (ULONG_PTR)HKEY_USERS          || v == 0x80000003UL) return L"HKU";
    if (v == (ULONG_PTR)HKEY_CURRENT_CONFIG || v == 0x80000005UL) return L"HKCC";
    return L"HKUNK";
}

std::pair<HKEY, std::wstring> RegistrySandbox::Redirect(HKEY root, const std::wstring& subkey) const {
    std::wstring sandbox_path = kSandboxRoot;
    sandbox_path += L'\\';
    sandbox_path += RootKeyName(root);
    if (!subkey.empty()) {
        sandbox_path += L'\\';
        sandbox_path += subkey;
    }
    // Always redirect to HKCU
    return { HKEY_CURRENT_USER, sandbox_path };
}

void RegistrySandbox::Cleanup() const {
    // RegDeleteTree (Vista+) removes the entire sandbox subtree without requiring
    // any stack-allocated name buffers — replacing the previous hand-rolled recursive
    // enumeration that allocated wchar_t name[256] on the stack and was susceptible
    // to STATUS_STACK_BUFFER_OVERRUN when Windows wrote names close to the 256-char
    // limit during RegEnumKeyExW.
    RegDeleteTree(HKEY_CURRENT_USER, kSandboxRoot);
}
