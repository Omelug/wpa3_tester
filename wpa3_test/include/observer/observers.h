#pragma once
#include <filesystem>
#include "config/RunStatus.h"

namespace wpa3_tester::observer{
    std::filesystem::path get_observer_folder(const RunStatus &rs, const std::string& observer_name);
}
