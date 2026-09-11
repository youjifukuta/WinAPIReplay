#pragma once
#include "config.h"
#include "log_types.h"
#include "api_executor.h"
#include <string>

class ResultWriter {
public:
    void Write(const Config&      cfg,
               const LogData&     log_data,
               const ReplayStats& stats) const;

private:
    static std::string CurrentIso8601();
};
