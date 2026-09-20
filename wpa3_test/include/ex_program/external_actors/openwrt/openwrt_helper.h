#pragma once
#include <filesystem>
#include <string>
#include "logger/log.h"

namespace wpa3_tester::openwrt {

// return value of <key> from the first block of <block_type> with name <block_name>
std::string uci_get_option(const std::filesystem::path &uci_file, std::string_view block_type,
		std::string_view block_name, std::string_view key);

// return value of <key> from the first block of <block_type> where <filter_key> == <filter_val>
// e.g. uci_get_option(f, "wifi-iface", "device", "radio0", "encryption")
std::string uci_get_option(const std::filesystem::path &uci_file, std::string_view block_type,
		std::string_view filter_key, std::string_view filter_val, std::string_view key);

// Parse AKM suite from an OpenWrt syslog-wrapped ap.log up to window.start_tp
// Lines contain "AP-STA-CONNECTED <mac> auth_alg=<alg>"; returns e.g. "sae\n(WPA3)"
std::string akm_from_openwrt_log(
		const std::filesystem::path &log_path, const Tins::HWAddress<6> &client_mac, TimeWindow window = {});

// Infer client MFP from an OpenWrt syslog-wrapped ap.log up to window.start_tp
// SAE auth_alg implies REQUIRED; PSK cannot be determined from these logs
std::string mfp_from_openwrt_log(
		const std::filesystem::path &log_path, const Tins::HWAddress<6> &client_mac, TimeWindow window = {});

// Returns true if "AP-STA-DISCONNECTED <client_mac>" appears in the log within the window
bool sta_disconnected_from_openwrt_log(
		const std::filesystem::path &log_path, const Tins::HWAddress<6> &client_mac, TimeWindow window = {});

}
