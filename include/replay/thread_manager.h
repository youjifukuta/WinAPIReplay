#pragma once
#include "log_types.h"
#include "api_executor.h"
#include <vector>
#include <map>
#include <thread>
#include <utility>

class ThreadManager {
public:
    ThreadManager(ApiExecutor& api_exec, bool single_thread, DWORD timeout_ms)
        : api_exec_(api_exec)
        , single_thread_(single_thread)
        , timeout_ms_(timeout_ms) {}

    void GroupByThread(const std::vector<LogEvent>& events);
    void Run();
    void WaitAll();

private:
    ApiExecutor& api_exec_;
    bool         single_thread_;
    DWORD        timeout_ms_;

    // key: (process_id, thread_id)
    std::map<std::pair<DWORD,DWORD>, std::vector<LogEvent>> groups_;
    std::vector<std::thread> threads_;
};
