#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <unordered_map>
#include <mutex>

class PointerMap {
public:
    void      Register(DWORD_PTR original_ptr, DWORD_PTR actual_ptr);
    DWORD_PTR Resolve(DWORD_PTR original_ptr) const;
    void      Invalidate(DWORD_PTR original_ptr);

private:
    std::unordered_map<DWORD_PTR, DWORD_PTR> map_;
    mutable std::mutex                        mutex_;
};
