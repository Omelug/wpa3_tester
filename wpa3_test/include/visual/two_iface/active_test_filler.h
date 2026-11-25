#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include <vector>
#include "config/RunSuiteStatus.h"
namespace wpa3_tester::visual::active_test_filler {
struct ActiveTestEntry {
	std::string test_name;
	std::optional<std::string> tx_driver;
	std::optional<std::string> rx_driver;
	std::optional<std::string> rx_mac;
	//result params
	int acked;
	int not_acked;
	bool success;
	static ActiveTestEntry parse(const std::filesystem::path &test_folder);
};
std::vector<ActiveTestEntry> collect_results(const std::filesystem::path &run_dir);
void generate_report(RunSuiteStatus &rss);
}
