#include <gtest/gtest.h>
#include "replay/path_sandbox.h"

class PathSandboxTest : public ::testing::Test {
protected:
    PathSandbox sb_{L"C:\\Sandbox"};
    PathSandbox sb_off_{L""};
};

TEST_F(PathSandboxTest, IsEnabledWhenRootSet) {
    EXPECT_TRUE(sb_.IsEnabled());
    EXPECT_FALSE(sb_off_.IsEnabled());
}

TEST_F(PathSandboxTest, RedirectsAbsoluteDrivePath) {
    // "C:\foo\bar.txt" → "C:\Sandbox\C_\foo\bar.txt"
    std::wstring r = sb_.Redirect(L"C:\\foo\\bar.txt");
    EXPECT_EQ(r, L"C:\\Sandbox\\C_\\foo\\bar.txt");
}

TEST_F(PathSandboxTest, RedirectsDifferentDriveLetter) {
    std::wstring r = sb_.Redirect(L"D:\\data\\sample.bin");
    EXPECT_EQ(r, L"C:\\Sandbox\\D_\\data\\sample.bin");
}

TEST_F(PathSandboxTest, RedirectsUncPath) {
    std::wstring r = sb_.Redirect(L"\\\\server\\share\\file.txt");
    EXPECT_EQ(r, L"C:\\Sandbox\\UNC\\server\\share\\file.txt");
}

TEST_F(PathSandboxTest, RedirectsRelativePath) {
    std::wstring r = sb_.Redirect(L"relative\\path.txt");
    EXPECT_EQ(r, L"C:\\Sandbox\\relative\\relative\\path.txt");
}

TEST_F(PathSandboxTest, RedirectsCurrentDirPath) {
    std::wstring r = sb_.Redirect(L".\\file.txt");
    EXPECT_EQ(r, L"C:\\Sandbox\\relative\\.\\file.txt");
}

TEST_F(PathSandboxTest, PassesThroughWhenDisabled) {
    // When root is empty, Redirect returns the path unchanged
    std::wstring r = sb_off_.Redirect(L"C:\\test.txt");
    EXPECT_EQ(r, L"C:\\test.txt");
}
