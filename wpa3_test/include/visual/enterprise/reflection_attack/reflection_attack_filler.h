#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include <vector>
#include "config/RunSuiteStatus.h"

namespace wpa3_tester::overview { struct HtmlGuard; }

namespace wpa3_tester::visual::reflection_attack_filler{
struct ReflectionAttackTestEntry{
	std::string test_name;
	std::string ap_driver;
	std::string ap_hostapd_version;
	std::string attacker_driver;
	//results params
	std::optional<bool> connected;

	static ReflectionAttackTestEntry parse(const std::filesystem::path &test_folder);
	static std::vector<ReflectionAttackTestEntry> collect_results(const std::filesystem::path &test_data_dir);
	static void render_table(overview::HtmlGuard &f, const std::string &title, const std::filesystem::path &suite_data_dir, const std::filesystem::
							path &page_dir
	);
};

void generate_report(RunSuiteStatus & rss);
}
