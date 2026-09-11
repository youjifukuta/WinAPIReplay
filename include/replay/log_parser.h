#pragma once
#include "log_types.h"
#include <string>

class LogParser {
public:
    LogData Parse(const std::string& path) const;
};
