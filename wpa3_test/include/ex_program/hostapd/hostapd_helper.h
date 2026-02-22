#pragma once
#include "logger/log.h"
namespace wpa3_tester::hostapd{
    //std::string get_wpa_supplicant(nlohmann::json setup);
    std::string get_hostapd(const std::string& version = "");
}
