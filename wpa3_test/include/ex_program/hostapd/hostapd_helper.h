#pragma once
#include <filesystem>
#include <optional>
#include <nlohmann/json.hpp>
#include "config/RunStatus.h"

namespace wpa3_tester::hostapd{
std::string get_wpa_supplicant(const std::string &version = "");
std::string get_hostapd(const std::string &version = "");
std::string get_hostapd_mana(const std::string &version = "");

// parses sae_password, fallback to psk from the generated <actor_name>_wpa_supplicant/hostapd.conf.
std::string get_password(const RunStatus &rs, const std::string &actor_name);
std::string get_ssid(const RunStatus &rs, const std::string &actor_name);
std::optional<bool> get_ocv(const RunStatus &rs, const std::string &actor_name);  // wpa_supplicant: ocv (network block key)
std::optional<bool> get_okc(const RunStatus &rs, const std::string &actor_name);  // hostapd: okc (top-level key)
std::string get_version(const RunStatus &rs, const std::string &actor_name);
// reads field from program_config json, falls back to parsing config_path file
std::string get_channel(const nlohmann::json &program_config, const std::string &config_path);

// parses ieee80211w from a wpa_supplicant.conf -> "OFF"/"OPTIONAL"/"REQUIRED", empty if absent
std::string get_mfp_from_supplicant(const std::filesystem::path &conf);

struct CrackResult{
	int total;
	int cracked;
};

// verify each WPA*02* hash from a creds file against psk using hcxpmktool
CrackResult crack_pmk_hashes(const std::filesystem::path &creds_file, const std::string &psk);

struct OpenSSLPaths{
	std::filesystem::path lib_dir;     // for LD_LIBRARY_PATH
	std::filesystem::path libcrypto;   // for LD_PRELOAD
	std::filesystem::path include_dir; // for -I when compiling against it
};

OpenSSLPaths get_openssl_paths(const std::string &tag);
std::string get_hostapd_with_openssl(const std::string &hostapd_version, const std::string &openssl_version);
}