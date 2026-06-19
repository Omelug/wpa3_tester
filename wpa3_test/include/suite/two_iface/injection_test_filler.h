#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include <utility>
#include <vector>
#include "config/RunSuiteStatus.h"

namespace wpa3_tester::suite::injection_test_filler{
struct InjectionTestEntry{
	std::string test_name;
	std::string tx_driver;
	std::string rx_driver;
	int tests_passed;
	int tests_total;
	std::vector<std::pair<std::string,std::string>> failures;
	std::optional<bool> passed; // value = all sub-tests passed

	static InjectionTestEntry parse(const std::filesystem::path &test_folder);
};

std::vector<InjectionTestEntry> get_results(const std::filesystem::path &run_dir);

void generate_report(RunSuiteStatus & rss);
}
