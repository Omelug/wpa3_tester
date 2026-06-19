#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include "config/RunSuiteStatus.h"

namespace wpa3_tester::suite::channel_switch_rogueAP{
struct CsaTestEntry{
	std::string name;
	std::string ap_mac;
	std::string ap_source;
	std::string client_mac;
	std::string client_source;
	std::string attacker_mac;
	std::string attacker_driver;
	std::string rogue_ap_mac;
	std::string rogue_ap_driver;

	//result params
	std::optional<bool> disconnected;
	std::optional<bool> ap_disconnected;
	std::optional<bool> rogue_ap_connected;

	std::optional<bool> ap_ocv;
	std::optional<bool> client_ocv;
	std::string client_mfp;
	std::optional<bool> passed;
	std::filesystem::path client_graph;
	std::filesystem::path ap_graph;
	std::filesystem::path rel_path;
};

CsaTestEntry parse_test_folder(const std::filesystem::path &test_folder);

void generate_report(RunSuiteStatus &rss);
}
