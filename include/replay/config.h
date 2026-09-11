#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <string>

struct Config {
    std::string  log_path;
    std::string  sig_path;
    bool         single_thread    = false;
    bool         dry_run          = false;
    DWORD        timeout_ms       = 5000;
    bool         verbose          = false;
    std::wstring sandbox_dir;
    bool         sandbox_registry = false;
    bool         net_sim          = false;
    bool         no_spawn         = false;
    bool         no_l1_executor  = false;
    std::string  result_json;
};

Config ParseArgs(int argc, char* argv[]);
