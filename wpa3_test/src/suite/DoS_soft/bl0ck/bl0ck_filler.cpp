#include <filesystem>
#include <fstream>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <yaml-cpp/yaml.h>

#include "config/RunStatus.h"
#include "config/RunSuiteStatus.h"
#include "logger/log.h"
#include "suite/DoS_soft/bl0ck/bl0ck_test_suites.h"
#include "suite/suite_helper.h"
#include "system/utils.h"

namespace wpa3_tester::suite::bl0ck_test_suites{
using namespace std;
using namespace filesystem;
using namespace nlohmann;

Bl0ckTestEntry parse_test_folder(const path &test_folder){
	Bl0ckTestEntry e;
	e.name = test_folder.filename().string();

	if(const auto result = helper::load_result_json(test_folder))
		e.passed = result->value("passed", false);

	const auto cfg_path = test_folder / "test_config.yaml";
	if(exists(cfg_path)){
		RunStatus rs{};
		rs.config_path(cfg_path);
		rs.run_folder(test_folder);
		rs.load_actor_interface_mapping();

		if(const auto it = rs.actors.find("access_point"); it != rs.actors.end()){
			e.ap_mac    = it->second->get_or(SK::mac,    "");
			e.ap_source = it->second->get_or(SK::source, "");
		}
		if(const auto it = rs.actors.find("client"); it != rs.actors.end()){
			e.client_mac    = it->second->get_or(SK::mac,    "");
			e.client_source = it->second->get_or(SK::source, "");
		}
		if(const auto it = rs.actors.find("attacker"); it != rs.actors.end()){
			e.attacker_mac    = it->second->get_or(SK::mac,         "");
			e.attacker_driver = it->second->get_or(SK::driver_name, "");
		}

		try{
			const auto cfg = YAML::LoadFile(cfg_path.string());
			if(cfg["attack_config"] && cfg["attack_config"]["attack_variant"])
				e.attack_variant = cfg["attack_config"]["attack_variant"].as<string>();
		} catch(...){}
	}

	return e;
}

vector<tuple<string, string, string, string, string, bool>> test_data(const path &run_dir){
	// test_name, ap_driver, client_driver, attacker_driver, attack_variant, passed
	vector<tuple<string, string, string, string, string, bool>> test_results;

	for(const auto &entry: directory_iterator(run_dir)){
		if(!entry.is_directory()) continue;

		const auto &test_folder = entry.path();
		const auto result = helper::load_result_json(test_folder);
		if(!result) continue;

		const bool passed    = result->value("passed", false);
		const string test_name = test_folder.filename().string();

		const auto drv = helper::load_test_drivers(test_folder);

		string attack_variant = "?";
		const auto config_path = test_folder / "test_config.yaml";
		if(exists(config_path)){
			const auto cfg = YAML::LoadFile(config_path.string());
			if(cfg["attack_config"] && cfg["attack_config"]["attack_variant"])
				attack_variant = cfg["attack_config"]["attack_variant"].as<string>();
		}

		test_results.emplace_back(test_name,
			helper::get_driver(drv, "access_point"),
			helper::get_driver(drv, "client"),
			helper::get_driver(drv, "attacker"),
			attack_variant, passed);
	}
	return test_results;
}

void generate_bl0ck_mac_gen_report(RunSuiteStatus &rss){
	log(LogLevel::INFO, "Generating bl0ck mac_gen test suite report");

	const auto run_dir = rss.run_folder();
	if(!exists(run_dir)){
		log(LogLevel::ERROR, "Run folder not found: {}", run_dir);
		return;
	}

	auto test_results = test_data(run_dir);
	auto report = helper::open_report(run_dir / "report.md");
	if(!report.is_open()) return;

	report << "# Bl0ck MAC Generator Test Suite Report\n\n";
	report << "Summary of Bl0ck attack tests across different driver combinations.\n\n";

	if(test_results.empty()){
		report << "No test results found.\n";
		report.close();
		return;
	}

	report << "## Test Results\n\n";
	report << "| Test | AP Driver | Client Driver | Attacker Driver | Variant | Result |\n";
	report << "|------|-----------|---------------|-----------------|---------|--------|\n";

	for(const auto &[test_name, ap_drv, cli_drv, att_drv, variant, passed]: test_results){
		const string name_cell   = exists(run_dir / test_name / "report.md")
			? "[" + test_name + "](" + test_name + "/report.md)" : test_name;
		const string result_link = "[" + string(passed ? "PASSED" : "FAILED") + "](" + test_name + "/result.json)";
		report << "| " << name_cell << " | " << ap_drv << " | " << cli_drv << " | "
			   << att_drv << " | " << variant << " | " << result_link << " |\n";
	}

	report << "\n## Summary\n\n";
	size_t passed_count = ranges::count_if(test_results, [](const auto &r){ return get<5>(r); });
	report << "- Total Tests: " << test_results.size() << "\n";
	report << "- Passed: " << passed_count << "\n";
	report << "- Failed: " << (test_results.size() - passed_count) << "\n";
	report << "- Success Rate: " << fixed << setprecision(1)
		   << (100.0 * passed_count / test_results.size()) << "%\n";

	report.close();
	set_public_perms(run_dir / "report.md");
	log(LogLevel::INFO, "Bl0ck mac_gen report generated: {}", (run_dir / "report.md").string());
}
}