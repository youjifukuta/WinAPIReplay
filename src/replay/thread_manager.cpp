#include "replay/thread_manager.h"
#include <algorithm>
#include <iostream>

// SEH and C++ destructors cannot coexist in the same scope (MSVC limitation).
// Isolate the execution loop in a plain C function so __try/__except can wrap it safely.
static void RunWithSEH(ApiExecutor& exec, const std::vector<const LogEvent*>& evs) {
    __try {
        int chk = 0;
        for (const auto* ev : evs) {
            exec.Execute(*ev);
            if (++chk % 10 == 0) {
                if (!HeapValidate(GetProcessHeap(), 0, NULL))
                    fprintf(stderr, "[HEAP_CORRUPT] first detected after seq=%d\n", ev->seq);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        fprintf(stderr, "[FATAL] Unhandled SEH in replay thread: code=0x%x\n",
                GetExceptionCode());
    }
}

static void RunWithSEH(ApiExecutor& exec, const std::vector<LogEvent>& evs) {
    __try {
        int chk = 0;
        for (const auto& ev : evs) {
            exec.Execute(ev);
            if (++chk % 10 == 0) {
                if (!HeapValidate(GetProcessHeap(), 0, NULL))
                    fprintf(stderr, "[HEAP_CORRUPT] first detected after seq=%d\n", ev.seq);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        fprintf(stderr, "[FATAL] Unhandled SEH in replay thread: code=0x%x\n",
                GetExceptionCode());
    }
}

void ThreadManager::GroupByThread(const std::vector<LogEvent>& events) {
    for (const auto& e : events) {
        auto key = std::make_pair(e.process_id, e.thread_id);
        groups_[key].push_back(e);
    }
    // Events are already in seq order from the log; maintain that order within each group
}

void ThreadManager::Run() {
    if (single_thread_) {
        // Collect all events sorted by seq and run in one thread
        std::vector<const LogEvent*> all;
        for (auto& [key, evs] : groups_)
            for (auto& e : evs) all.push_back(&e);
        std::sort(all.begin(), all.end(),
                  [](const LogEvent* a, const LogEvent* b){ return a->seq < b->seq; });

        threads_.emplace_back([this, all = std::move(all)]() {
            RunWithSEH(api_exec_, all);
        });
    } else {
        for (auto& [key, evs] : groups_) {
            threads_.emplace_back([this, &evs = evs]() {
                RunWithSEH(api_exec_, evs);
            });
        }
    }
}

void ThreadManager::WaitAll() {
    for (auto& t : threads_)
        if (t.joinable()) t.join();
}
