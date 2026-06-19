#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include "config/RunSuiteStatus.h"

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
	std::optional<bool> disconnected;
	//std::optional<bool> passed;

	static Bl0ckTestEntry parse(const std::filesystem::path &test_folder);
};

void generate_bl0ck_mac_gen_report(RunSuiteStatus &rss);
}
