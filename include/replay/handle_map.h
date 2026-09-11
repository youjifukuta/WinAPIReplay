#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <unordered_map>
#include <mutex>

class HandleMap {
public:
    void      Register(DWORD_PTR original, DWORD_PTR actual);
    DWORD_PTR Resolve(DWORD_PTR original) const;
    // Like Resolve but returns 0 instead of the original value for unmapped handles.
    // Use this in Layer2 dispatch to prevent malware handle values from accidentally
    // operating on WinAPIReplay's own kernel objects.
    DWORD_PTR SafeResolve(DWORD_PTR original) const;
    void      Invalidate(DWORD_PTR original);
    bool      IsPredefined(DWORD_PTR v) const;
    bool      HasMapping(DWORD_PTR original) const;

private:
    std::unordered_map<DWORD_PTR, DWORD_PTR> map_;
    mutable std::mutex                        mutex_;
};
