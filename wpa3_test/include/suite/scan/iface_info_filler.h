#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include <vector>
#include "config/RunSuiteStatus.h"

namespace wpa3_tester::suite::iface_info_filler{
struct IfaceInfoTestEntry{
	std::string test_name;
	std::string hw_summary;
	std::string driver_summary;
	std::filesystem::path report_md;
	std::optional<bool> channel_switch_ok;
	std::optional<int>  channel_switch_us;
	std::optional<bool> netns_move_ok;
	std::optional<int>  netns_move_ms;
	std::optional<int>  netns_return_ms;

	static IfaceInfoTestEntry parse(const std::filesystem::path &test_folder);
};

std::vector<IfaceInfoTestEntry> collect_results(const std::filesystem::path &run_dir);

void generate_report(RunSuiteStatus & rss);
}
