#include "replay/pid_map.h"

void PidMap::Register(DWORD original_pid, DWORD actual_pid) {
    if (original_pid == 0) return;
    std::lock_guard<std::mutex> lock(mutex_);
    map_[original_pid] = actual_pid;
}

DWORD PidMap::Resolve(DWORD original_pid) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = map_.find(original_pid);
    return (it != map_.end()) ? it->second : original_pid;
}
