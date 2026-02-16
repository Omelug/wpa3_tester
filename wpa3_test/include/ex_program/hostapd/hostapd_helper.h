#pragma once
#include "logger/log.h"
namespace wpa3_tester::hostpd{
    std::string get_wpa_supplicant(nlohmann::json setup);
    std::string get_hostapd(nlohmann::json setup);
}
