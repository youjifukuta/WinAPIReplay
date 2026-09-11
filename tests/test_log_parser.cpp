#include <gtest/gtest.h>
#include "replay/log_parser.h"
#include <fstream>
#include <filesystem>

namespace fs = std::filesystem;

// Helper: write a temp JSON file and return its path
static std::string WriteTempJson(const std::string& content) {
    std::string path = (fs::temp_directory_path() / "winapi_replay_test.json").string();
    std::ofstream f(path, std::ios::trunc);
    f << content;
    return path;
}

static const char* kMinimalLog = R"({
  "meta": {
    "target_process": "test.exe",
    "process_bits": 64,
    "collected_at": "2026-01-01T00:00:00Z",
    "frida_version": "16.0",
    "os": "Windows 10"
  },
  "events": [
    {
      "seq": 1,
      "process_id": 1234,
      "timestamp": 0.001,
      "thread_id": 5678,
      "api_name": "CreateFileW",
      "args": ["C:\\foo.txt", 0, "0x80000000", null],
      "inline_handles": [],
      "out_handles": {},
      "return_val": "0x00000004",
      "status": "success"
    }
  ]
})";

TEST(LogParser, ParsesMeta) {
    auto path = WriteTempJson(kMinimalLog);
    auto data = LogParser{}.Parse(path);
    EXPECT_EQ(data.meta.target_process, "test.exe");
    EXPECT_EQ(data.meta.process_bits, 64);
}

TEST(LogParser, ParsesEventCount) {
    auto path = WriteTempJson(kMinimalLog);
    auto data = LogParser{}.Parse(path);
    ASSERT_EQ(data.events.size(), 1u);
}

TEST(LogParser, ParsesEventFields) {
    auto path = WriteTempJson(kMinimalLog);
    auto data = LogParser{}.Parse(path);
    const auto& e = data.events[0];
    EXPECT_EQ(e.seq, 1);
    EXPECT_EQ(e.process_id, 1234u);
    EXPECT_NEAR(e.timestamp, 0.001, 1e-9);
    EXPECT_EQ(e.thread_id, 5678u);
    EXPECT_EQ(e.api_name, "CreateFileW");
    EXPECT_EQ(e.return_val, "0x00000004");
    EXPECT_EQ(e.status, "success");
}

TEST(LogParser, ParsesArgTypes) {
    auto path = WriteTempJson(kMinimalLog);
    auto data = LogParser{}.Parse(path);
    const auto& args = data.events[0].args;
    ASSERT_EQ(args.size(), 4u);

    // arg[0] = string → wstring
    ASSERT_TRUE(std::holds_alternative<std::wstring>(args[0]));
    EXPECT_EQ(std::get<std::wstring>(args[0]), L"C:\\foo.txt");

    // arg[1] = 0 → int64_t
    ASSERT_TRUE(std::holds_alternative<std::int64_t>(args[1]));
    EXPECT_EQ(std::get<std::int64_t>(args[1]), 0);

    // arg[2] = "0x80000000" → int64_t (hex)
    ASSERT_TRUE(std::holds_alternative<std::int64_t>(args[2]));
    EXPECT_EQ(std::get<std::int64_t>(args[2]), (std::int64_t)0x80000000LL);

    // arg[3] = null → nullptr_t
    ASSERT_TRUE(std::holds_alternative<std::nullptr_t>(args[3]));
}

TEST(LogParser, ParsesEmptyInlineHandlesAndOutHandles) {
    auto path = WriteTempJson(kMinimalLog);
    auto data = LogParser{}.Parse(path);
    const auto& e = data.events[0];
    EXPECT_TRUE(e.inline_handles.empty());
    EXPECT_TRUE(e.out_handles.empty());
}

TEST(LogParser, ParsesNonEmptyInlineHandles) {
    static const char* json = R"({
  "meta": {"target_process":"a.exe","process_bits":64,"collected_at":"","frida_version":"","os":""},
  "events": [
    {"seq":1,"process_id":1,"timestamp":0.0,"thread_id":1,"api_name":"WaitForMultipleObjects",
     "args":[],"inline_handles":["0x00000004","0x00000008"],"out_handles":{},
     "return_val":"0x0","status":"success"}
  ]
})";
    auto data = LogParser{}.Parse(WriteTempJson(json));
    ASSERT_EQ(data.events[0].inline_handles.size(), 2u);
    EXPECT_EQ(data.events[0].inline_handles[0], "0x00000004");
    EXPECT_EQ(data.events[0].inline_handles[1], "0x00000008");
}

TEST(LogParser, ParsesNonEmptyOutHandles) {
    static const char* json = R"({
  "meta": {"target_process":"a.exe","process_bits":64,"collected_at":"","frida_version":"","os":""},
  "events": [
    {"seq":1,"process_id":1,"timestamp":0.0,"thread_id":1,"api_name":"CreateFileW",
     "args":[],"inline_handles":[],"out_handles":{"hFile":"0x00000004"},
     "return_val":"0x00000004","status":"success"}
  ]
})";
    auto data = LogParser{}.Parse(WriteTempJson(json));
    ASSERT_EQ(data.events[0].out_handles.size(), 1u);
    EXPECT_EQ(data.events[0].out_handles[0].key, "hFile");
    ASSERT_TRUE(std::holds_alternative<std::string>(data.events[0].out_handles[0].value));
    EXPECT_EQ(std::get<std::string>(data.events[0].out_handles[0].value), "0x00000004");
}

TEST(LogParser, ParsesOutHandleWithNumericValue) {
    static const char* json = R"({
  "meta": {"target_process":"a.exe","process_bits":64,"collected_at":"","frida_version":"","os":""},
  "events": [
    {"seq":1,"process_id":1,"timestamp":0.0,"thread_id":1,"api_name":"CreateProcessW",
     "args":[],"inline_handles":[],"out_handles":{"dwProcessId":1234},
     "return_val":"0x1","status":"success"}
  ]
})";
    auto data = LogParser{}.Parse(WriteTempJson(json));
    ASSERT_EQ(data.events[0].out_handles.size(), 1u);
    EXPECT_EQ(data.events[0].out_handles[0].key, "dwProcessId");
    ASSERT_TRUE(std::holds_alternative<DWORD>(data.events[0].out_handles[0].value));
    EXPECT_EQ(std::get<DWORD>(data.events[0].out_handles[0].value), (DWORD)1234);
}

TEST(LogParser, ThrowsOnMissingFile) {
    EXPECT_THROW(LogParser{}.Parse("nonexistent_file_xyz.json"), std::runtime_error);
}

TEST(LogParser, MultipleEvents) {
    static const char* json = R"({
  "meta": {"target_process":"a.exe","process_bits":64,"collected_at":"","frida_version":"","os":""},
  "events": [
    {"seq":1,"process_id":1,"timestamp":0.0,"thread_id":1,"api_name":"A",
     "args":[],"inline_handles":[],"out_handles":{},"return_val":"0x0","status":"success"},
    {"seq":2,"process_id":1,"timestamp":0.001,"thread_id":1,"api_name":"B",
     "args":[],"inline_handles":[],"out_handles":{},"return_val":"0x0","status":"success"}
  ]
})";
    auto data = LogParser{}.Parse(WriteTempJson(json));
    ASSERT_EQ(data.events.size(), 2u);
    EXPECT_EQ(data.events[0].api_name, "A");
    EXPECT_EQ(data.events[1].api_name, "B");
}
