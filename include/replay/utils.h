#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <string>
#include <sstream>
#include <iomanip>

inline std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (n <= 0) return {};
    std::wstring ws(n - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, ws.data(), n);
    return ws;
}

inline std::string WideToUtf8(const std::wstring& ws) {
    if (ws.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string s(n - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, s.data(), n, nullptr, nullptr);
    return s;
}

inline DWORD_PTR HexToPtr(const std::string& s) {
    if (s.empty()) return 0;
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        return (DWORD_PTR)std::stoull(s, nullptr, 16);
    return (DWORD_PTR)std::stoull(s, nullptr, 0);
}

inline std::string FormatHex(DWORD_PTR v, int width = 8) {
    std::ostringstream ss;
    ss << "0x" << std::uppercase << std::hex << std::setfill('0') << std::setw(width) << v;
    return ss.str();
}
