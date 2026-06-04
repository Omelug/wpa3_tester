#pragma once
#include <filesystem>
#include "logger/log.h"

namespace wpa3_tester::hostapd{
std::string get_wpa_supplicant(const std::string &version = "");
std::string get_hostapd(const std::string &version = "");
std::string get_hostapd_mana(const std::string &version = "");

struct CrackResult {
    int total;
    int cracked;
};

// Verify each WPA*02* hash from a wpa.creds file against psk using hcxpmktool.
CrackResult crack_pmk_hashes(const std::filesystem::path &creds_file, const std::string &psk);
}