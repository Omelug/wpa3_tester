#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include "config/RunSuiteStatus.h"
#include "overview/described.h"
#include "overview/html_guard.h"

namespace wpa3_tester::visual::expected_vht_beacon_suite {

struct ExpVhtTestEntry {
	// display fields - populated in parse(), not from result.json
	std::string name;
	std::string ap_mac;
	std::string ap_source;
	std::string client_mac;
	std::string client_source;
	std::string attacker_mac;
	std::string attacker_driver;
	std::string rogue_ap_mac;
	std::string rogue_ap_driver;

	// result fields - names must match result.json keys (auto-loaded by load_result_default)
	int disconnect_count = 0;
	std::optional<bool> dmesg_change_mode_disconnect;
	std::optional<bool> ap_disconnected;
	std::optional<bool> rogue_ap_connected;
	std::optional<bool> cracked;
	described_str client_mfp;
	described_str ap_WPA_support;
	described_str client_WPA_support;
	described_str conn_WPA_version;

	static ExpVhtTestEntry parse(const std::filesystem::path &test_folder);
	static void render_table(overview::HtmlGuard &f, const std::string &title,
			const std::filesystem::path &suite_data_dir, const std::filesystem::path &page_dir,
			const std::string &t_name);
	static void render_table_dlink(overview::HtmlGuard &f, const std::string &title,
			const std::filesystem::path &suite_data_dir, const std::filesystem::path &page_dir,
			const std::string &t_name);
	static void generate_report(RunSuiteStatus &rss);
};

}
