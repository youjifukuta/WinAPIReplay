#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <unordered_map>
#include <mutex>

class PidMap {
public:
    void  Register(DWORD original_pid, DWORD actual_pid);
    DWORD Resolve(DWORD original_pid) const;

private:
    std::unordered_map<DWORD, DWORD> map_;
    mutable std::mutex               mutex_;
};
