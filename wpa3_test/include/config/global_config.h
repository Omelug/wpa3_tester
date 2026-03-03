#pragma once
#include <nlohmann/json.hpp>

namespace wpa3_tester{
    nlohmann::json& get_global_config();
}