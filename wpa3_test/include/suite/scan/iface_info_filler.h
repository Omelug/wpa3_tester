#pragma once
#include <filesystem>
#include <string>
#include <vector>
#include "config/RunSuiteStatus.h"

namespace wpa3_tester::suite::iface_info_filler{
struct IfaceInfoTestEntry{
	std::string test_name;
	std::string hw_summary;
	std::filesystem::path report_md;

	static IfaceInfoTestEntry parse(const std::filesystem::path &test_folder);
};

std::vector<IfaceInfoTestEntry> get_results(const std::filesystem::path &run_dir);

void generate_report(RunSuiteStatus & rss);
}
