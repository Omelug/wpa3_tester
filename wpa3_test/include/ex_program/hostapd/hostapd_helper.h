#pragma once
#include "logger/log.h"

namespace wpa3_tester::hostapd{
std::string get_wpa_supplicant(const std::string &version = "");
std::string get_hostapd(const std::string &version = "");
}