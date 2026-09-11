#include <gtest/gtest.h>
#include "replay/result_writer.h"
#include "replay/api_executor.h"
#include "replay/config.h"
#include "replay/log_types.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <filesystem>

namespace fs = std::filesystem;
using json = nlohmann::json;

static std::string TempOut(const char* name) {
    return (fs::temp_directory_path() / name).string();
}

static Config MakeCfg(const std::string& out_path) {
    Config cfg;
    cfg.result_json = out_path;
    return cfg;
}

// ── transforms present ────────────────────────────────────────────

TEST(ResultWriter, TransformsSerializedToJson) {
    std::string out = TempOut("rw_transforms.json");

    ReplayStats stats;
    EventResult r;
    r.seq           = 1;
    r.api_name      = "CreateFileW";
    r.outcome       = "success";
    r.actual_return = "0x00000004";
    r.transforms.push_back({0, "C:\\Users\\victim\\evil.exe",
                                "C:\\Sandbox\\C_\\Users\\victim\\evil.exe"});
    stats.results.push_back(r);
    stats.total = 1; stats.success = 1;

    ResultWriter{}.Write(MakeCfg(out), LogData{}, stats);

    std::ifstream f(out);
    ASSERT_TRUE(f.is_open());
    json j; f >> j;

    ASSERT_EQ(j["results"].size(), 1u);
    const auto& tx = j["results"][0]["transforms"];
    ASSERT_TRUE(tx.is_array());
    ASSERT_EQ(tx.size(), 1u);
    EXPECT_EQ(tx[0]["param_index"].get<int>(), 0);
    EXPECT_EQ(tx[0]["original"].get<std::string>(),  "C:\\Users\\victim\\evil.exe");
    EXPECT_EQ(tx[0]["rewritten"].get<std::string>(), "C:\\Sandbox\\C_\\Users\\victim\\evil.exe");
}

TEST(ResultWriter, MultipleTransformsAllSerialized) {
    std::string out = TempOut("rw_multi_transforms.json");

    ReplayStats stats;
    EventResult r;
    r.seq      = 5;
    r.api_name = "MoveFileExW";
    r.outcome  = "success";
    r.actual_return = "0x00000001";
    r.transforms.push_back({0, "C:\\Users\\victim\\old.txt",
                                "C:\\Sandbox\\C_\\Users\\victim\\old.txt"});
    r.transforms.push_back({1, "C:\\Users\\victim\\new.txt",
                                "C:\\Sandbox\\C_\\Users\\victim\\new.txt"});
    stats.results.push_back(r);
    stats.total = 1; stats.success = 1;

    ResultWriter{}.Write(MakeCfg(out), LogData{}, stats);

    std::ifstream f(out);
    ASSERT_TRUE(f.is_open());
    json j; f >> j;

    const auto& tx = j["results"][0]["transforms"];
    ASSERT_TRUE(tx.is_array());
    ASSERT_EQ(tx.size(), 2u);
    EXPECT_EQ(tx[0]["param_index"].get<int>(), 0);
    EXPECT_EQ(tx[1]["param_index"].get<int>(), 1);
    EXPECT_EQ(tx[1]["original"].get<std::string>(),  "C:\\Users\\victim\\new.txt");
    EXPECT_EQ(tx[1]["rewritten"].get<std::string>(), "C:\\Sandbox\\C_\\Users\\victim\\new.txt");
}

// ── no transforms → null ─────────────────────────────────────────

TEST(ResultWriter, EmptyTransformsIsNull) {
    std::string out = TempOut("rw_no_transforms.json");

    ReplayStats stats;
    EventResult r;
    r.seq      = 1;
    r.api_name = "CloseHandle";
    r.outcome  = "success";
    // no transforms
    stats.results.push_back(r);
    stats.total = 1; stats.success = 1;

    ResultWriter{}.Write(MakeCfg(out), LogData{}, stats);

    std::ifstream f(out);
    ASSERT_TRUE(f.is_open());
    json j; f >> j;

    ASSERT_EQ(j["results"].size(), 1u);
    EXPECT_TRUE(j["results"][0]["transforms"].is_null());
}

// ── Extension A: NetSim transform (same SandboxTransform mechanism) ──────────

TEST(ResultWriter, NetSimTransformSerializedAsNormalTransform) {
    std::string out = TempOut("rw_netsim_transform.json");

    ReplayStats stats;
    EventResult r;
    r.seq      = 7;
    r.api_name = "WSAConnect";
    r.outcome  = "success";
    r.transforms.push_back({1, "176.123.9.142:4444", "127.0.0.1"});
    stats.results.push_back(r);
    stats.total = 1; stats.success = 1;

    ResultWriter{}.Write(MakeCfg(out), LogData{}, stats);

    std::ifstream f(out);
    json j; f >> j;
    const auto& tx = j["results"][0]["transforms"];
    ASSERT_EQ(tx.size(), 1u);
    EXPECT_EQ(tx[0]["param_index"].get<int>(), 1);
    EXPECT_EQ(tx[0]["original"].get<std::string>(),  "176.123.9.142:4444");
    EXPECT_EQ(tx[0]["rewritten"].get<std::string>(), "127.0.0.1");
}

// ── Extension B: process_events serialization ─────────────────────────────────

TEST(ResultWriter, ProcessEvents_EmptyArrayWhenNone) {
    std::string out = TempOut("rw_proc_empty.json");

    ReplayStats stats;
    stats.total = 0;
    ResultWriter{}.Write(MakeCfg(out), LogData{}, stats);

    std::ifstream f(out);
    json j; f >> j;
    ASSERT_TRUE(j.contains("process_events"));
    EXPECT_TRUE(j["process_events"].is_array());
    EXPECT_EQ(j["process_events"].size(), 0u);
}

TEST(ResultWriter, ProcessEvents_SingleEntryAllFields) {
    std::string out = TempOut("rw_proc_single.json");

    ReplayStats stats;
    ProcessEvent pe;
    pe.seq               = 42;
    pe.api_name          = "CreateProcessW";
    pe.application       = "C:\\Windows\\system32\\cmd.exe";
    pe.command_line      = "cmd.exe /c evil.bat";
    pe.current_directory = "C:\\Users\\victim";
    pe.outcome           = "skipped";
    stats.process_events.push_back(pe);
    stats.total = 1; stats.skipped = 1;

    ResultWriter{}.Write(MakeCfg(out), LogData{}, stats);

    std::ifstream f(out);
    json j; f >> j;
    ASSERT_EQ(j["process_events"].size(), 1u);
    const auto& e = j["process_events"][0];
    EXPECT_EQ(e["seq"].get<int>(),      42);
    EXPECT_EQ(e["api_name"].get<std::string>(), "CreateProcessW");
    EXPECT_EQ(e["application"].get<std::string>(),  "C:\\Windows\\system32\\cmd.exe");
    EXPECT_EQ(e["command_line"].get<std::string>(),  "cmd.exe /c evil.bat");
    EXPECT_EQ(e["current_directory"].get<std::string>(), "C:\\Users\\victim");
    EXPECT_EQ(e["outcome"].get<std::string>(), "skipped");
}

TEST(ResultWriter, ProcessEvents_NullFieldsForEmptyStrings) {
    std::string out = TempOut("rw_proc_null_fields.json");

    ReplayStats stats;
    ProcessEvent pe;
    pe.seq          = 10;
    pe.api_name     = "CreateProcessA";
    pe.command_line = "malware.exe";
    // application and current_directory are empty strings → should be null in JSON
    pe.outcome      = "skipped";
    stats.process_events.push_back(pe);
    stats.total = 1;

    ResultWriter{}.Write(MakeCfg(out), LogData{}, stats);

    std::ifstream f(out);
    json j; f >> j;
    const auto& e = j["process_events"][0];
    EXPECT_TRUE(e["application"].is_null());
    EXPECT_FALSE(e["command_line"].is_null());
    EXPECT_TRUE(e["current_directory"].is_null());
}

TEST(ResultWriter, ProcessEvents_MultipleEntriesPreserveOrder) {
    std::string out = TempOut("rw_proc_multi.json");

    ReplayStats stats;
    for (int i = 1; i <= 3; i++) {
        ProcessEvent pe;
        pe.seq         = i;
        pe.api_name    = "CreateProcessW";
        pe.command_line = "proc" + std::to_string(i) + ".exe";
        pe.outcome     = "skipped";
        stats.process_events.push_back(pe);
    }
    stats.total = 3;

    ResultWriter{}.Write(MakeCfg(out), LogData{}, stats);

    std::ifstream f(out);
    json j; f >> j;
    ASSERT_EQ(j["process_events"].size(), 3u);
    EXPECT_EQ(j["process_events"][0]["seq"].get<int>(), 1);
    EXPECT_EQ(j["process_events"][1]["seq"].get<int>(), 2);
    EXPECT_EQ(j["process_events"][2]["seq"].get<int>(), 3);
    EXPECT_EQ(j["process_events"][2]["command_line"].get<std::string>(), "proc3.exe");
}

// ── transforms in registry event ─────────────────────────────────

TEST(ResultWriter, RegistryTransformSerializedWithCorrectFields) {
    std::string out = TempOut("rw_registry_transform.json");

    ReplayStats stats;
    EventResult r;
    r.seq      = 3;
    r.api_name = "RegCreateKeyExW";
    r.outcome  = "success";
    r.transforms.push_back({1,
        "HKLM\\SOFTWARE\\Microsoft\\Windows",
        "HKCU\\Software\\WinAPIReplaySandbox\\HKLM\\SOFTWARE\\Microsoft\\Windows"});
    stats.results.push_back(r);
    stats.total = 1; stats.success = 1;

    ResultWriter{}.Write(MakeCfg(out), LogData{}, stats);

    std::ifstream f(out);
    ASSERT_TRUE(f.is_open());
    json j; f >> j;

    const auto& tx = j["results"][0]["transforms"];
    ASSERT_EQ(tx.size(), 1u);
    EXPECT_EQ(tx[0]["param_index"].get<int>(), 1);
    EXPECT_EQ(tx[0]["original"].get<std::string>(),
              "HKLM\\SOFTWARE\\Microsoft\\Windows");
    EXPECT_EQ(tx[0]["rewritten"].get<std::string>(),
              "HKCU\\Software\\WinAPIReplaySandbox\\HKLM\\SOFTWARE\\Microsoft\\Windows");
}
