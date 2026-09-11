#include "replay/handle_map.h"

static const DWORD_PTR kPredefined[] = {
    // 32-bit forms (from 32-bit process logs)
    0x80000000ULL,
    0x80000001ULL,
    0x80000002ULL,
    0x80000003ULL,
    0x80000005ULL,
    // 64-bit sign-extended forms (from 64-bit process logs)
    (DWORD_PTR)HKEY_CLASSES_ROOT,   // 0xFFFFFFFF80000000
    (DWORD_PTR)HKEY_CURRENT_USER,   // 0xFFFFFFFF80000001
    (DWORD_PTR)HKEY_LOCAL_MACHINE,  // 0xFFFFFFFF80000002
    (DWORD_PTR)HKEY_USERS,          // 0xFFFFFFFF80000003
    (DWORD_PTR)HKEY_CURRENT_CONFIG, // 0xFFFFFFFF80000005
    (DWORD_PTR)INVALID_HANDLE_VALUE,// 0xFFFFFFFFFFFFFFFF
};

bool HandleMap::IsPredefined(DWORD_PTR v) const {
    for (auto p : kPredefined)
        if (v == p) return true;
    return false;
}

void HandleMap::Register(DWORD_PTR original, DWORD_PTR actual) {
    if (IsPredefined(original) || original == 0) return;
    std::lock_guard<std::mutex> lock(mutex_);
    map_[original] = actual;
}

DWORD_PTR HandleMap::Resolve(DWORD_PTR original) const {
    if (original == 0) return 0;
    if (IsPredefined(original)) {
        // Normalize 32-bit truncated form (from 32-bit logs) to proper 64-bit sign-extended form.
        // On 64-bit Windows HKEY_LOCAL_MACHINE == (HKEY)0xFFFFFFFF80000002, not (HKEY)0x80000002.
        switch (original) {
        case 0x80000000ULL: return (DWORD_PTR)HKEY_CLASSES_ROOT;
        case 0x80000001ULL: return (DWORD_PTR)HKEY_CURRENT_USER;
        case 0x80000002ULL: return (DWORD_PTR)HKEY_LOCAL_MACHINE;
        case 0x80000003ULL: return (DWORD_PTR)HKEY_USERS;
        case 0x80000005ULL: return (DWORD_PTR)HKEY_CURRENT_CONFIG;
        default:            return original;  // already 64-bit form or INVALID_HANDLE_VALUE
        }
    }
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = map_.find(original);
    return (it != map_.end()) ? it->second : original;
}

DWORD_PTR HandleMap::SafeResolve(DWORD_PTR original) const {
    if (original == 0) return 0;
    if (IsPredefined(original)) {
        switch (original) {
        case 0x80000000ULL: return (DWORD_PTR)HKEY_CLASSES_ROOT;
        case 0x80000001ULL: return (DWORD_PTR)HKEY_CURRENT_USER;
        case 0x80000002ULL: return (DWORD_PTR)HKEY_LOCAL_MACHINE;
        case 0x80000003ULL: return (DWORD_PTR)HKEY_USERS;
        case 0x80000005ULL: return (DWORD_PTR)HKEY_CURRENT_CONFIG;
        default:            return original;
        }
    }
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = map_.find(original);
    // Return 0 for unmapped handles rather than the original malware-process value.
    // This prevents Layer2 callers from accidentally passing a malware handle value
    // that happens to be valid in WinAPIReplay's own handle table.
    return (it != map_.end()) ? it->second : 0;
}

void HandleMap::Invalidate(DWORD_PTR original) {
    std::lock_guard<std::mutex> lock(mutex_);
    map_.erase(original);
}

bool HandleMap::HasMapping(DWORD_PTR original) const {
    if (original == 0) return false;
    if (IsPredefined(original)) return true;
    std::lock_guard<std::mutex> lock(mutex_);
    return map_.count(original) > 0;
}
