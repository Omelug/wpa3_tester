#pragma once
#include <iomanip>
#include <string>

namespace wpa3_tester::firmware{
    std::string get_ath_masker_mac(const std::string& attacker_mac);
}