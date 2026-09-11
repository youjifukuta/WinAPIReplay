#include "replay/pointer_map.h"

void PointerMap::Register(DWORD_PTR original_ptr, DWORD_PTR actual_ptr) {
    if (original_ptr == 0) return;
    std::lock_guard<std::mutex> lock(mutex_);
    map_[original_ptr] = actual_ptr;
}

DWORD_PTR PointerMap::Resolve(DWORD_PTR original_ptr) const {
    if (original_ptr == 0) return 0;
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = map_.find(original_ptr);
    return (it != map_.end()) ? it->second : original_ptr;
}

void PointerMap::Invalidate(DWORD_PTR original_ptr) {
    if (original_ptr == 0) return;
    std::lock_guard<std::mutex> lock(mutex_);
    map_.erase(original_ptr);
}
