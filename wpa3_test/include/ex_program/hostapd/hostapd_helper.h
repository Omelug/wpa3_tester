#pragma once
#include <filesystem>
#include <optional>
#include <nlohmann/json.hpp>
#include "config/RunStatus.h"
#include "logger/log.h"

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
std::string get_openssl_version(const RunStatus &rs, const std::string &actor_name);

// reads field from program_config json, falls back to parsing config_path file
std::string get_channel(const nlohmann::json &program_config, const std::string &config_path);

// parses ieee80211w from a wpa_supplicant.conf -> "OFF"/"OPTIONAL"/"REQUIRED", empty if absent
std::string get_mfp_from_supplicant(const std::filesystem::path &conf);

// parse AKM suite from a hostapd -d log up to window.start_tp; returns e.g. "00-0F-AC:8\n(WPA3)"
std::string akm_from_ap_log(const std::filesystem::path &log_path, const Tins::HWAddress<6> &client_mac, TimeWindow window = {});
// parse client MFP from MFPR/MFPC fields in a hostapd -d log up to window.start_tp
std::string mfp_from_ap_log(const std::filesystem::path &log_path, const Tins::HWAddress<6> &client_mac, TimeWindow window = {});
// parse client AKM suites from RSN IE in EAPOL-Key in a hostapd -d log up to window.start_tp (e.g. "SAE WPA-PSK")
std::string client_akm_from_ap_log(const std::filesystem::path &log_path, const Tins::HWAddress<6> &client_mac, TimeWindow window = {});

// Find Probe Requests from client_mac in ap_log after start_tag until END_tag/END_STOP_tag.
// Returns "ch: X Y Z" (scanned channels from DS Params or freq), empty if none found.
std::string client_scanning_from_ap_log(const std::filesystem::path &ap_log,
										 const Tins::HWAddress<6> &client_mac, TimeWindow window = {});

// computes secondary BSSID for OWE transition mode (flips LSB of last octet)
std::string owe_trans_bssid(const std::string &primary_mac);

struct CrackResult{
	int total;
	int cracked;
};

// parse hccapx v4 binary (written by hostapd-mana) -> WPA*02* hashcat lines
std::vector<std::string> hccapx_to_wpa_hashes(const std::filesystem::path &hccapx_path);

// verify each WPA*02* hash from a creds file against psk using hcxpmktool
CrackResult crack_pmk_hashes(const std::filesystem::path &creds_file, const std::string &psk);

std::string get_conf_value(const std::filesystem::path &cfg, std::initializer_list<std::string_view> keys);

struct OpenSSLPaths{
	std::filesystem::path lib_dir;     // for LD_LIBRARY_PATH
	std::filesystem::path libcrypto;   // for LD_PRELOAD
	std::filesystem::path include_dir; // for -I when compiling against it
};

OpenSSLPaths get_openssl_paths(const std::string &tag);
std::string get_hostapd_with_openssl(const std::string &hostapd_version, const std::string &openssl_version);

void apply_wpa_overrides(const std::filesystem::path &cfg, const nlohmann::json &overrides);
}