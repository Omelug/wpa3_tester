#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include <vector>
#include "config/RunSuiteStatus.h"
namespace wpa3_tester::overview {
struct HtmlGuard;
}
namespace wpa3_tester::visual::amsdu_filler {
struct AmsduEntry {
	std::string test_name;
	std::string ap_mac;
	std::string client_mac;
	std::optional<std::string> client_driver;
	std::optional<std::string> rogue_client_driver;
	std::optional<std::string> rogue_ap_driver;
	std::string ssid;
	// result.json fields (matched by field name via load_result_default)
	std::optional<bool> got_mitm;
	std::optional<bool> injected_26144;
	std::optional<bool> flipped_24588;
	std::optional<bool> dns_queried;
	std::filesystem::path rel_path;
	static AmsduEntry parse(const std::filesystem::path &test_folder);
	static std::vector<AmsduEntry> collect_results(const std::filesystem::path &suite_data_dir);
	static void render_table(overview::HtmlGuard &f, const std::string &title,
		const std::filesystem::path &suite_data_dir, const std::filesystem::path &page_dir, const std::string &t_name);
	static void generate_report(RunSuiteStatus &rss);
};
}
