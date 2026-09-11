#include "replay/path_sandbox.h"

std::wstring PathSandbox::Redirect(const std::wstring& path) const {
    if (root_.empty()) return path;

    std::wstring result = root_;
    if (!result.empty() && result.back() != L'\\') result += L'\\';

    // UNC: \\server\share → <root>\UNC\server\share
    if (path.size() >= 2 && path[0] == L'\\' && path[1] == L'\\') {
        result += L"UNC\\";
        result += path.substr(2);
        return result;
    }

    // 絶対パス: C:\foo → <root>\C_\foo
    if (path.size() >= 2 && path[1] == L':') {
        wchar_t drive = path[0];
        result += drive;
        result += L'_';
        if (path.size() > 2) result += path.substr(2);
        return result;
    }

    // 相対パス: → <root>\relative\...
    result += L"relative\\";
    result += path;
    return result;
}
