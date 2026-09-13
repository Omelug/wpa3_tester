#pragma once
#include <filesystem>
#include <string>
#include "logger/log.h"

namespace wpa3_tester::openwrt {

// parse UCI config file
// return the value of option <key> in the block of type <block_type> named <block_name>
// returns empty string if not found.
std::string uci_get_option(const std::filesystem::path &uci_file, std::string_view block_type,
		std::string_view block_name, std::string_view key);

// Parse AKM suite from an OpenWrt syslog-wrapped ap.log up to window.start_tp
// Lines contain "AP-STA-CONNECTED <mac> auth_alg=<alg>"; returns e.g. "sae\n(WPA3)"
std::string akm_from_openwrt_log(
		const std::filesystem::path &log_path, const Tins::HWAddress<6> &client_mac, TimeWindow window = {});

// Infer client MFP from an OpenWrt syslog-wrapped ap.log up to window.start_tp
// SAE auth_alg implies REQUIRED; PSK cannot be determined from these logs
std::string mfp_from_openwrt_log(
		const std::filesystem::path &log_path, const Tins::HWAddress<6> &client_mac, TimeWindow window = {});

}
