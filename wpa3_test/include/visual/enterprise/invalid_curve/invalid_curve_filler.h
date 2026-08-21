#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include <vector>
#include "config/RunSuiteStatus.h"

namespace wpa3_tester::overview { struct HtmlGuard; }

namespace wpa3_tester::visual::invalid_curve_filler{
struct InvalidCurveTestEntry{
	std::string test_name;
	std::string ap_hostapd_version;
	std::string ap_openssl_version;
	std::string ap_driver;
	std::string attacker_driver;
	//result params
	std::optional<bool> connected;

	static InvalidCurveTestEntry parse(const std::filesystem::path &test_folder);
	static std::vector<InvalidCurveTestEntry>
	collect_results(const std::filesystem::path &test_data_dir);
	static void render_table(overview::HtmlGuard &f,
							const std::string &title, const std::filesystem::path &suite_data_dir, const std::filesystem::path &page_dir
	);
};

void generate_report(const RunSuiteStatus & rss);
}