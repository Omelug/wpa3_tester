#pragma once
#include <nlohmann/json.hpp>

namespace wpa3_tester{
    inline std::filesystem::path global_config_path(const std::filesystem::path &project_root_dir= PROJECT_ROOT_DIR);
    nlohmann::json& get_global_config(const std::filesystem::path &project_root_dir = PROJECT_ROOT_DIR, bool reset = false);
}