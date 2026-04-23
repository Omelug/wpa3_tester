#pragma once

#include <string>
#include <nlohmann/json.hpp>
#include "config/RunStatus.h"

namespace wpa3_tester::hostapd{
std::string hostapd_config(const std::string &run_folder, const nlohmann::json &ap_setup);
std::string wpa_supplicant_config(const std::string &run_folder, const nlohmann::json &client_setup);

void run_hostapd(RunStatus &rs, const std::string &actor_name);
void run_wpa_supplicant(RunStatus &rs, const std::string &actor_name);
void run_hostapd_mana(RunStatus &rs, const std::string &actor_name);
}