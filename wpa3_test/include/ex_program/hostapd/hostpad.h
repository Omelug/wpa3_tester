#pragma once

#include <string>
#include <nlohmann/json.hpp>

namespace wpa3_tester{
    std::string hostapd_config(const std::string& run_folder, const nlohmann::json& ap_setup);
    std::string wpa_supplicant_config(const std::string& run_folder, const nlohmann::json& client_setup);
}