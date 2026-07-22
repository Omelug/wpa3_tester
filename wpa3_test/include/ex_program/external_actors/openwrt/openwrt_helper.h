#pragma once
#include <filesystem>
#include <string>

namespace wpa3_tester::openwrt{

// Parse AKM suite from an OpenWrt syslog-wrapped ap.log up to stop_tag.
// Lines contain "AP-STA-CONNECTED <mac> auth_alg=<alg>"; returns e.g. "sae\n(WPA3)".
std::string akm_from_openwrt_log(const std::filesystem::path &log_path, const std::string &stop_tag);

// Infer client MFP from an OpenWrt syslog-wrapped ap.log up to stop_tag.
// SAE auth_alg implies REQUIRED; PSK cannot be determined from these logs.
std::string mfp_from_openwrt_log(const std::filesystem::path &log_path, const std::string &stop_tag);

}
