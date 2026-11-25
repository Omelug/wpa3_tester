#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include "config/RunSuiteStatus.h"
namespace wpa3_tester::visual::channel_switch_filler {
struct CsaVersionTestEntry {
	std::string name;
	std::string hostapd_version;
	std::string supplicant_version;
	std::optional<std::string> ap_driver;
	std::optional<std::string> client_driver;
	std::optional<std::string> attacker_driver;
	std::optional<std::string> rogue_ap_driver;
	std::string new_channel;
	std::string attack_time;
	std::filesystem::path client_graph;
	std::filesystem::path ap_graph;
	static CsaVersionTestEntry parse(const std::filesystem::path &test_folder);
	static void generate_report(RunSuiteStatus &rss);
};
}
