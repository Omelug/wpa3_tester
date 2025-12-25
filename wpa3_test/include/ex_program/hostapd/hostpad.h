#pragma once

#include <string>
#include <nlohmann/json.hpp>

void hostapd_config(const std::string& run_folder, const nlohmann::json& ap_setup);
void wpa_supplicant_config(const string& run_folder, const nlohmann::json& client_setup);