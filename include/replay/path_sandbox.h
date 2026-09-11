#pragma once
#include <string>

class PathSandbox {
public:
    explicit PathSandbox(const std::wstring& root) : root_(root) {}
    bool         IsEnabled() const { return !root_.empty(); }
    std::wstring Redirect(const std::wstring& path) const;

private:
    std::wstring root_;
};
