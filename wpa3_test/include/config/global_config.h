#pragma once
#include <nlohmann/json.hpp>
#include "config/Run_Config.h"
#include "system/utils.h"

namespace wpa3_tester{
std::filesystem::path global_config_path(const std::filesystem::path &project_root_dir = root_dir());
nlohmann::json &get_global_config(const std::filesystem::path &project_root_dir = root_dir(), bool reset = false);
const Run_Config &get_global_run_config(const std::filesystem::path &project_root_dir = root_dir(),
										bool reset = false
);
}