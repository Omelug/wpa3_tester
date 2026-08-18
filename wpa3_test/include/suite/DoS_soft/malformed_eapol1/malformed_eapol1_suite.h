#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include "config/RunSuiteStatus.h"
#include "overview/html_guard.h"

namespace wpa3_tester::suite::malformed_eapol1_filler{
struct MalformedEapol1TestEntry{
	std::string test_name;
	std::string ap_mac;
	std::string ap_source;
	std::string ap_driver;

	std::string client_mac;
	std::string client_source;
	std::optional<std::string> client_driver;
	std::string client_version;

	// ------- result params
	std::string attacker_mac;
	std::string attacker_driver;
	std::string rogue_ap_mac;
	std::string rogue_ap_driver;

	described_bool client_disconnected;
	std::optional<bool> ap_disconnected;

	described_str client_mfp;
	described_str ap_WPA_support;
	described_str client_WPA_support;
	described_str conn_WPA_version;
	described_str client_scanning;
	std::optional<bool> rogue_ap_connected;
	bool cracked;

	std::filesystem::path sta_graph;
	std::filesystem::path ap_graph;

	static MalformedEapol1TestEntry parse(const std::filesystem::path &test_folder);
	static std::vector<MalformedEapol1TestEntry> collect_results(const std::filesystem::path &test_data_dir);
	static void render_table(overview::HtmlGuard &f, const std::string &title, const std::filesystem::path &suite_data_dir, const std::filesystem::
							path &page_dir);
	static void generate_report(RunSuiteStatus & rss);
};
}
