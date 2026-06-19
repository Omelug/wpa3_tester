#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include <vector>
#include "config/RunSuiteStatus.h"

namespace wpa3_tester::suite::wpa3_trans_downgrade_filler {

struct Wpa3TransDowngradeTestEntry {
	std::string test_name;
	std::string ap_driver;
	std::string client_driver;
	bool	disconnected;
	bool	downgrade_seen;

	static Wpa3TransDowngradeTestEntry parse(const std::filesystem::path &test_folder);
};

std::vector<Wpa3TransDowngradeTestEntry> get_results(const std::filesystem::path &run_dir);

void setup_suite(const RunSuiteStatus &rss);
void generate_report(RunSuiteStatus &rss);

}