#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include <vector>
#include "config/RunSuiteStatus.h"

namespace wpa3_tester::suite::owe_trans_filler {

struct OweTransTestEntry {
	std::string test_name;
	std::string ap_driver;
	std::string client_driver;
	std::string attacker_driver;
	int         probe_count;
	bool        disconnected;
	std::optional<bool> passed; // nullopt = no result.json; value = vulnerable
};

OweTransTestEntry parse_test_folder(const std::filesystem::path &test_folder);
std::vector<OweTransTestEntry> get_results(const std::filesystem::path &run_dir);

void generate_report(RunSuiteStatus &rss);

}