#include <filesystem>
#include <fstream>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <yaml-cpp/yaml.h>

#include "config/RunStatus.h"
#include "config/RunSuiteStatus.h"
#include "logger/log.h"
#include "suite/DoS_soft/bl0ck/bl0ck_test_suites.h"
#include "system/utils.h"

namespace wpa3_tester::suite::bl0ck_test_suites{
using namespace std;
using namespace filesystem;
using namespace nlohmann;

void generate_bl0ck_mac_gen_report(RunSuiteStatus &rss){
	log(LogLevel::INFO, "Generating bl0ck mac_gen test suite report");

	const auto run_dir = rss.run_folder();
	if(!exists(run_dir)){
		log(LogLevel::ERROR, "Run folder not found: {}", run_dir.string());
		return;
	}

	// test_name, ap_driver, client_driver, attacker_driver, attack_variant, passed
	vector<tuple<string, string, string, string, string, bool>> test_results;

	for(const auto &entry: directory_iterator(run_dir)){
		if(!entry.is_directory()) continue;

		const auto test_folder = entry.path();
		const auto result_json = test_folder / "result.json";

		if(!exists(result_json)) continue;

		ifstream result_file(result_json);
		json result_data = json::parse(result_file);
		result_file.close();

		bool passed = result_data.value("passed", false);
		string test_name = test_folder.filename().string();

		string ap_driver = "?";
		string client_driver = "?";
		string attacker_driver = "?";
		string attack_variant = "?";

		const auto config_path = test_folder / "test_config.yaml";
		if(exists(config_path)){
			RunStatus rs{};
			rs.config_path(config_path);
			rs.run_folder(test_folder);
			rs.load_actor_interface_mapping();

			if(auto ap = rs.actors.find("access_point"); ap != rs.actors.end())
				ap_driver = ap->second->get_or(SK::driver_name, "?");
			if(auto cli = rs.actors.find("client"); cli != rs.actors.end())
				client_driver = cli->second->get_or(SK::driver_name, "?");
			if(auto att = rs.actors.find("attacker"); att != rs.actors.end())
				attacker_driver = att->second->get_or(SK::driver_name, "?");

			const auto cfg = YAML::LoadFile(config_path.string());
			if(cfg["attack_config"] && cfg["attack_config"]["attack_variant"])
				attack_variant = cfg["attack_config"]["attack_variant"].as<string>();
		}

		test_results.emplace_back(test_name, ap_driver, client_driver, attacker_driver, attack_variant, passed);
	}

	ofstream report(run_dir / "report.md");
	set_public_perms(run_dir / "report.md");
	if(!report.is_open()){
		log(LogLevel::ERROR, "Failed to create report.md");
		return;
	}

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
		report << "| " << test_name << " | " << ap_drv << " | " << cli_drv << " | "
			   << att_drv << " | " << variant << " | " << (passed ? "PASSED" : "FAILED") << " |\n";
	}

	report << "\n## Summary\n\n";
	size_t passed_count = ranges::count_if(test_results, [](const auto &r){ return get<5>(r); });
	report << "- **Total Tests:** " << test_results.size() << "\n";
	report << "- **Passed:** " << passed_count << "\n";
	report << "- **Failed:** " << (test_results.size() - passed_count) << "\n";
	report << "- **Success Rate:** " << fixed << setprecision(1)
		   << (100.0 * passed_count / test_results.size()) << "%\n";

	report.close();
	log(LogLevel::INFO, "Bl0ck mac_gen report generated: {}", (run_dir / "report.md").string());
}
}