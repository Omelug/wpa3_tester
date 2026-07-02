#pragma once
#include <filesystem>
#include <string>
#include <vector>
#include "config/RunSuiteStatus.h"

namespace wpa3_tester::suite::active_test_filler{
struct ActiveTestEntry{
	std::string test_name;
	std::string tx_driver;
	std::string rx_driver;
	//result params
	int acked;
	int not_acked;
	bool success;

	static ActiveTestEntry parse(const std::filesystem::path &test_folder);
};

std::vector<ActiveTestEntry> get_results(const std::filesystem::path &run_dir);

void generate_report(RunSuiteStatus & rss);
}
