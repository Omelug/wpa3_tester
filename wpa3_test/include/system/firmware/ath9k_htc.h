#pragma once
#include <string>

namespace wpa3_tester::firmware{
    std::string get_random_ath_masker_mac(const std::string& attacker_mac);
    void load_ath_masker();
}