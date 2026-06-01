#pragma once
#include <nlohmann/json.hpp>
#include "config/Run_Config.h"

namespace wpa3_tester{
std::filesystem::path global_config_path(const std::filesystem::path &project_root_dir = PROJECT_ROOT_DIR);
nlohmann::json &get_global_config(const std::filesystem::path &project_root_dir = PROJECT_ROOT_DIR, bool reset = false);
const Run_Config &get_global_run_config(const std::filesystem::path &project_root_dir = PROJECT_ROOT_DIR, bool reset = false);
}