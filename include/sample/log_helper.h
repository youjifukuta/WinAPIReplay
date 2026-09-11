#pragma once
#include <cstdio>
#include <initializer_list>
#include <utility>
#include <windows.h>

inline void LogCallOk(const char* api, const char* detail) {
    printf("[CALL] %-22s  %-40s  status=success\n", api, detail);
}

inline void LogCallErr(const char* api, const char* detail, DWORD err) {
    printf("[CALL] %-22s  %-40s  status=error  error=%lu\n", api, detail, err);
}

inline void LogCallOkOut(const char* api, const char* detail,
                          std::initializer_list<std::pair<const char*, DWORD_PTR>> outs) {
    printf("[CALL] %-22s  %-40s  status=success", api, detail);
    for (const auto& kv : outs)
        printf("  %s=0x%08llX", kv.first, (unsigned long long)kv.second);
    printf("\n");
}
