#pragma once
#include <filesystem>
#include <string>
#include <vector>
#include "config/RunSuiteStatus.h"

namespace wpa3_tester::overview { struct HtmlGuard; }

namespace wpa3_tester::suite::owe_trans_filler{
struct OweTransTestEntry{
	std::string test_name;
	std::string ap_driver;
	std::string client_driver;
	std::string attacker_driver;

	//results json
	int broadcast_probe_count;
	int ssid_probe_count;
	bool disconnected;

	static OweTransTestEntry parse(const std::filesystem::path &test_folder);
	static void render_table(overview::HtmlGuard &f,
	                         const std::vector<std::filesystem::path> &folders,
	                         const std::filesystem::path &page_dir);
};

std::vector<OweTransTestEntry> get_results(const std::filesystem::path &run_dir);

void generate_report(RunSuiteStatus & rss);
}