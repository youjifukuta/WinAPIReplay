#include "replay/log_parser.h"
#include "replay/utils.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <stdexcept>

using json = nlohmann::json;

static ArgValue ParseArgValue(const json& v) {
    if (v.is_null())   return std::nullptr_t{};
    if (v.is_number()) return static_cast<std::int64_t>(v.get<std::int64_t>());
    if (v.is_string()) {
        std::string s = v.get<std::string>();
        if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
            return static_cast<std::int64_t>(std::stoull(s, nullptr, 16));
        return Utf8ToWide(s);
    }
    return std::int64_t{0};
}

LogData LogParser::Parse(const std::string& path) const {
    std::ifstream f(path);
    if (!f.is_open())
        throw std::runtime_error("Cannot open log file: " + path);

    json root;
    f >> root;

    LogData data;

    // meta
    auto& m = root["meta"];
    data.meta.target_process = m.value("target_process", "unknown.exe");
    data.meta.process_bits   = m.value("process_bits", 64);
    data.meta.collected_at   = m.value("collected_at", "");
    data.meta.frida_version  = m.value("frida_version", "");
    data.meta.os             = m.value("os", "");

    // events
    for (auto& ev : root["events"]) {
        LogEvent e;
        e.seq        = ev.value("seq", 0);
        e.process_id = ev.value("process_id", 0);
        e.timestamp  = ev.value("timestamp", 0.0);
        e.thread_id  = ev.value("thread_id", 0);
        e.api_name   = ev.value("api_name", "");
        e.return_val = ev.value("return_val", "0x00000000");
        e.status     = ev.value("status", "");

        for (auto& a : ev.value("args", json::array()))
            e.args.push_back(ParseArgValue(a));

        for (auto& ih : ev.value("inline_handles", json::array()))
            e.inline_handles.push_back(ih.get<std::string>());

        auto& oh = ev.value("out_handles", json::object());
        for (auto it = oh.begin(); it != oh.end(); ++it) {
            OutHandle h;
            h.key = it.key();
            if (it.value().is_string())
                h.value = it.value().get<std::string>();
            else if (it.value().is_number())
                h.value = static_cast<DWORD>(it.value().get<std::uint32_t>());
            else
                h.value = std::string("0x00000000");
            e.out_handles.push_back(std::move(h));
        }

        data.events.push_back(std::move(e));
    }

    return data;
}
