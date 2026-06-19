#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include <vector>
#include "config/RunSuiteStatus.h"

namespace wpa3_tester::suite::reflection_attack_filler{
struct ReflectionAttackTestEntry{
	std::string test_name;
	std::string ap_driver;
	std::string attacker_driver;
	std::optional<bool> passed; // nullopt = no result.json

	static ReflectionAttackTestEntry parse(const std::filesystem::path &test_folder);
};

std::vector<ReflectionAttackTestEntry> get_results(const std::filesystem::path &run_dir);

void setup_suite(const RunSuiteStatus &rss);
void generate_report(RunSuiteStatus & rss);
}
