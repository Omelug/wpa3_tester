#pragma once
#include <filesystem>
#include <string>
#include <vector>
#include "config/RunSuiteStatus.h"

namespace wpa3_tester::overview { struct HtmlGuard; }

namespace wpa3_tester::suite::bl0ck_test_suites{
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

	static Bl0ckTestEntry parse(const std::filesystem::path &test_folder);
	static void render_table(overview::HtmlGuard &f,
	                         const std::vector<std::filesystem::path> &folders,
	                         const std::filesystem::path &page_dir);
};

void generate_bl0ck_mac_gen_report(RunSuiteStatus &rss);
}
