#pragma once
#include <string>

namespace wpa3_tester::firmware{
std::string get_random_ath_masker_mac(const std::string &attacker_mac);
void load_ath_masker(bool git_install);
void unload_ath_masker();
void load_ath9k_noorder_change(bool git_install);
void unload_ath9k_noorder_change();
void disable_custom_drivers();
}