#pragma once
#include <filesystem>
#include "config/RunStatus.h"

namespace wpa3_tester::observer{
    std::filesystem::path get_observer_folder(const RunStatus &rs, const std::string& observer_name);
    void add_nets(const RunStatus& run_status, std::vector<std::string>& command, const std::string& src_name);
}
