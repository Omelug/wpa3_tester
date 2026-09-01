#pragma once
#include <filesystem>
#include <string>
#include <vector>
#include "config/RunSuiteStatus.h"
#include "overview/described.h"

namespace wpa3_tester::overview { struct HtmlGuard; }

namespace wpa3_tester::visual::bl0ck_test_suites{
struct Bl0ckTestEntry{
	std::string name;
	std::string ap_mac;
	std::string ap_source;
	std::string client_mac;
	std::string client_source;
	std::string attacker_mac;
	std::string attacker_driver;
	std::string attack_variant;

	//result params
	int disconnect_count = 0;
	described_bool bl0ck_iperf;

	static Bl0ckTestEntry parse(const std::filesystem::path &test_folder);
	static void render_table(overview::HtmlGuard &f, const std::string &title,
							 const std::filesystem::path &suite_data_dir,
							 const std::filesystem::path &page_dir,
							 const std::string &t_name);
	static void generate_report(RunSuiteStatus &rss);
};

}
