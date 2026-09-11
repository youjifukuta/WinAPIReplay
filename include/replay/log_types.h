#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <string>
#include <vector>
#include <variant>

// JSON の args 各要素の型表現
using ArgValue = std::variant<std::wstring, std::int64_t, std::nullptr_t>;

// out_handles の値: ハンドル系は hex 文字列、dwProcessId/dwThreadId は DWORD
using OutHandleValue = std::variant<std::string, DWORD>;

struct OutHandle {
    std::string    key;
    OutHandleValue value;
};

struct LogEvent {
    int                      seq        = 0;
    DWORD                    process_id = 0;
    double                   timestamp  = 0.0;
    DWORD                    thread_id  = 0;
    std::string              api_name;
    std::vector<ArgValue>    args;
    std::vector<std::string> inline_handles;
    std::vector<OutHandle>   out_handles;
    std::string              return_val;
    std::string              status;
};

struct LogMeta {
    std::string target_process;
    int         process_bits = 64;
    std::string collected_at;
    std::string frida_version;
    std::string os;
};

struct LogData {
    LogMeta               meta;
    std::vector<LogEvent> events;
};
