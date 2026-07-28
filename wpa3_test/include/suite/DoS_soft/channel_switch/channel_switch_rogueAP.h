#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include <vector>
#include "config/RunSuiteStatus.h"
#include "overview/described.h"

namespace wpa3_tester::overview { struct HtmlGuard; }

namespace wpa3_tester::suite::channel_switch_rogueAP{

struct CsaTestEntry{
	std::string name;
	std::string ap_mac;
	std::string ap_source;
	std::string client_mac;
	std::string client_source;
	std::string attacker_mac;
	std::string attacker_driver;
	std::string rogue_ap_mac;
	std::string rogue_ap_driver;

	// ------- result params
	described_bool client_disconnected;
	std::optional<bool> ap_disconnected;
	described_bool ap_ocv;
	described_bool client_ocv;

	described_str client_mfp;
	described_str ap_WPA_support;
	described_str client_WPA_support;
	described_str conn_WPA_version;
	described_str client_scanning;
	std::optional<bool> rogue_ap_connected;

	//std::filesystem::path client_graph;
	//std::filesystem::path ap_graph;
	//std::filesystem::path rel_path;
};

CsaTestEntry parse_test_folder(const std::filesystem::path &test_folder);

void render_table(overview::HtmlGuard &f,
                  const std::vector<std::filesystem::path> &folders,
                  const std::filesystem::path &page_dir);

void generate_report(RunSuiteStatus &rss);
}
