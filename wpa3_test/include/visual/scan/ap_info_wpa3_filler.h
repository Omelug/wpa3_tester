#pragma once
#include <filesystem>
#include <string>
#include <vector>
#include "config/RunSuiteStatus.h"

namespace wpa3_tester::overview { struct HtmlGuard; }

namespace wpa3_tester::visual::ap_info_wpa3_filler{
struct ApInfoWpa3TestEntry{
	std::string test_name;

	// result params
	std::string mac;
	std::string ssid;
	std::string mfp;
	std::string akm;
	bool beacon_found;
	bool acm_triggered = false;
	std::vector<std::string> stations;

	static ApInfoWpa3TestEntry parse(const std::filesystem::path &test_folder);
	static void render_table(overview::HtmlGuard &f, const std::string &title,
		const std::filesystem::path &suite_data_dir, const std::filesystem::path &page_dir
	);
};

void generate_report(RunSuiteStatus & rss);
}
