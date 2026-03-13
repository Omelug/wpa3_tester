#pragma once
#include <filesystem>
#include "config/RunStatus.h"
#include "logger/log.h"

namespace wpa3_tester::observer{
    std::filesystem::path get_observer_folder(const RunStatus &rs, const std::string& observer_name);
    void add_nets(const RunStatus& run_status, std::vector<std::string>& command, const std::string& src_name);
    void transform_to_relative(std::vector<LogTimePoint>& times, const LogTimePoint &start_time);
}
