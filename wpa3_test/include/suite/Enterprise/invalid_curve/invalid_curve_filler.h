#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include <vector>
#include "config/RunSuiteStatus.h"

namespace wpa3_tester::overview { struct HtmlGuard; }

namespace wpa3_tester::suite::invalid_curve_filler{
struct InvalidCurveTestEntry{
	std::string test_name;
	std::string ap_driver;
	std::string attacker_driver;
	//result params
	std::optional<bool> passed;

	static InvalidCurveTestEntry parse(const std::filesystem::path &test_folder);
	static void render_table(overview::HtmlGuard &f,
	                         const std::vector<std::filesystem::path> &folders,
	                         const std::filesystem::path &page_dir);
};

std::vector<InvalidCurveTestEntry> get_results(const std::filesystem::path &run_dir);

void setup_suite(const RunSuiteStatus &rss);
void generate_report(const RunSuiteStatus & rss);
}