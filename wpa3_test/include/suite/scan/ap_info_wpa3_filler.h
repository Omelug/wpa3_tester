#pragma once
#include <filesystem>
#include <string>
#include <vector>
#include "config/RunSuiteStatus.h"

namespace wpa3_tester::suite::ap_info_wpa3_filler{
struct ApInfoWpa3TestEntry{
	std::string test_name;

	// result params
	std::string mac;
	std::string ssid;
	std::string mfp;
	std::string akm;
	bool beacon_found;
	bool acm_triggered = false;

	static ApInfoWpa3TestEntry parse(const std::filesystem::path &test_folder);
};

std::vector<ApInfoWpa3TestEntry> get_results(const std::filesystem::path &run_dir);

void generate_report(RunSuiteStatus & rss);
}
