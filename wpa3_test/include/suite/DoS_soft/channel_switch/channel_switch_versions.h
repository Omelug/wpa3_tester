#pragma once
#include <filesystem>
#include <string>
#include "config/RunSuiteStatus.h"

namespace wpa3_tester::suite::channel_switch_filler{
struct CsaVersionTestEntry{
	std::string name;
	std::string hostapd_version;
	std::string supplicant_version;

	std::string ap_driver;
	std::string client_driver;
	std::string attacker_driver;
	std::string rogue_ap_driver;

	std::string new_channel;
	std::string attack_time;

	std::filesystem::path client_graph;
	std::filesystem::path ap_graph;
};

CsaVersionTestEntry parse_test_folder(const std::filesystem::path &test_folder);

void generate_report(RunSuiteStatus & rss);
}
