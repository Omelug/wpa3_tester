#pragma once
#include <nlohmann/json.hpp>

namespace wpa3_tester{
    nlohmann::json& get_global_config(const std::filesystem::path &project_root_dir = PROJECT_ROOT_DIR, bool reset = false);
}