#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include "config/RunSuiteStatus.h"

namespace wpa3_tester::suite::malformed_eapol1_filler{
struct MalformedEapol1TestEntry{
	std::string test_name;
	std::string ap_driver;
	std::string client_driver;
	std::string client_version;
	std::string attacker_driver;
	//result params
	int disconnect_count;
	std::optional<bool> rogue_ap_connected;

	std::filesystem::path sta_graph;
	std::filesystem::path ap_graph;

	static MalformedEapol1TestEntry parse(const std::filesystem::path &test_folder);
};

void generate_report(RunSuiteStatus & rss);
}