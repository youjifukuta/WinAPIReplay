#include "replay/result_writer.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>
#include <windows.h>
#include <iomanip>
#include <sstream>

using json = nlohmann::json;

std::string ResultWriter::CurrentIso8601() {
    SYSTEMTIME st{};
    GetSystemTime(&st);
    std::ostringstream ss;
    ss << std::setfill('0')
       << st.wYear        << "-"
       << std::setw(2) << st.wMonth  << "-"
       << std::setw(2) << st.wDay    << "T"
       << std::setw(2) << st.wHour   << ":"
       << std::setw(2) << st.wMinute << ":"
       << std::setw(2) << st.wSecond << "Z";
    return ss.str();
}

void ResultWriter::Write(const Config&      cfg,
                          const LogData&     log_data,
                          const ReplayStats& stats) const {
    json out;

    out["meta"]["log_file"]            = cfg.log_path;
    out["meta"]["replayed_at"]         = CurrentIso8601();
    out["meta"]["replay_tool_version"] = "1.0.0";
    out["meta"]["options"]["sandbox"]          = !cfg.sandbox_dir.empty();
    out["meta"]["options"]["sandbox_registry"] = cfg.sandbox_registry;
    out["meta"]["options"]["net_sim"]          = cfg.net_sim;
    out["meta"]["options"]["no_spawn"]         = cfg.no_spawn;
    out["meta"]["options"]["dry_run"]          = cfg.dry_run;
    out["meta"]["options"]["single_thread"]    = cfg.single_thread;
    out["meta"]["options"]["timeout_ms"]       = cfg.timeout_ms;

    out["summary"]["total"]   = stats.total;
    out["summary"]["success"] = stats.success;
    out["summary"]["failed"]  = stats.failed;
    out["summary"]["skipped"] = stats.skipped;
    out["summary"]["approx"]  = stats.approx;

    json results = json::array();
    for (const auto& r : stats.results) {
        json entry;
        entry["seq"]           = r.seq;
        entry["api_name"]      = r.api_name;
        entry["outcome"]       = r.outcome;
        entry["actual_return"] = r.actual_return.empty() ? json(nullptr) : json(r.actual_return);
        entry["note"]          = r.note.empty()          ? json(nullptr) : json(r.note);
        if (!r.transforms.empty()) {
            json tx = json::array();
            for (const auto& t : r.transforms)
                tx.push_back({{"param_index", t.param_index},
                               {"original",    t.original},
                               {"rewritten",   t.rewritten}});
            entry["transforms"] = std::move(tx);
        } else {
            entry["transforms"] = nullptr;
        }
        results.push_back(std::move(entry));
    }
    out["results"] = std::move(results);

    // Extension B: process creation telemetry
    if (!stats.process_events.empty()) {
        json pevts = json::array();
        for (const auto& pe : stats.process_events) {
            json entry;
            entry["seq"]               = pe.seq;
            entry["api_name"]          = pe.api_name;
            entry["application"]       = pe.application.empty()       ? json(nullptr) : json(pe.application);
            entry["command_line"]      = pe.command_line.empty()      ? json(nullptr) : json(pe.command_line);
            entry["current_directory"] = pe.current_directory.empty() ? json(nullptr) : json(pe.current_directory);
            entry["outcome"]           = pe.outcome.empty()           ? json(nullptr) : json(pe.outcome);
            pevts.push_back(std::move(entry));
        }
        out["process_events"] = std::move(pevts);
    } else {
        out["process_events"] = json::array();
    }

    std::ofstream f(cfg.result_json);
    if (!f.is_open()) {
        std::cerr << "[WARN] Cannot write result JSON: " << cfg.result_json << "\n";
        return;
    }
    f << out.dump(2);
}
