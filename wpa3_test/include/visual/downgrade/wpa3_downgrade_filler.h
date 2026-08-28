#pragma once
#include "config/RunSuiteStatus.h"
#include "overview/described.h"
#include <filesystem>
#include <string>
#include <vector>

namespace wpa3_tester::overview { struct HtmlGuard; }

namespace wpa3_tester::visual::wpa3_downgrade_filler{
struct Wpa3TransDowngradeTestEntry{
	std::string test_name;
	std::string ap_mac;
	std::string client_mac;

	std::string ap_driver;
	std::string client_driver;
	bool disconnected = false;
	bool downgrade_seen = false;

	described_str ap_wpa3_trans_disable;

	static Wpa3TransDowngradeTestEntry parse(const std::filesystem::path &test_folder);
	static std::vector<Wpa3TransDowngradeTestEntry> collect_results(const std::filesystem::path &test_data_dir);
	static void render_table(overview::HtmlGuard &f, const std::string &title,
							 const std::filesystem::path &suite_data_dir,
							 const std::filesystem::path &page_dir,
							 const std::string &t_name);
};

std::vector<Wpa3TransDowngradeTestEntry> collect_results(const std::filesystem::path &run_dir);

void setup_suite(const RunSuiteStatus &rss);
void generate_report(RunSuiteStatus & rss);
}