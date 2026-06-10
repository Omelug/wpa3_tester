#pragma once
#include <filesystem>
#include "config/RunStatus.h"
#include "logger/log.h"

namespace wpa3_tester::hostapd{
std::string get_wpa_supplicant(const std::string &version = "");
std::string get_hostapd(const std::string &version = "");
std::string get_hostapd_mana(const std::string &version = "");

// parses sae_password, fallback to psk from the generated <actor_name>_wpa_supplicant/hostapd.conf.
std::string get_password(const RunStatus &rs, const std::string &actor_name);

struct CrackResult {
    int total;
    int cracked;
};

// verify each WPA*02* hash from a creds file against psk using hcxpmktool
CrackResult crack_pmk_hashes(const std::filesystem::path &creds_file, const std::string &psk);

struct OpenSSLPaths {
    std::filesystem::path lib_dir;     // for LD_LIBRARY_PATH
    std::filesystem::path libcrypto;   // for LD_PRELOAD
    std::filesystem::path include_dir; // for -I when compiling against it
};

OpenSSLPaths get_openssl_paths(const std::string &version);
std::string get_hostapd_with_openssl(const std::string &hostapd_version, const std::string &openssl_version);

}