#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include <vector>
#include "config/RunSuiteStatus.h"

namespace wpa3_tester::suite::invalid_curve_filler {

struct InvalidCurveTestEntry {
	std::string test_name;
	std::string ap_driver;
	std::string attacker_driver;
	std::optional<bool> passed; // nullopt = no result.json
};

InvalidCurveTestEntry parse_test_folder(const std::filesystem::path &test_folder);
std::vector<InvalidCurveTestEntry> get_results(const std::filesystem::path &run_dir);

void setup_suite(const RunSuiteStatus &rss);
void generate_report(RunSuiteStatus &rss);

}