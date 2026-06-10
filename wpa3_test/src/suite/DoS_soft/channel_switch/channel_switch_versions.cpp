#include <filesystem>
#include <fstream>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <yaml-cpp/yaml.h>

#include "config/RunSuiteStatus.h"
#include "logger/log.h"
#include "suite/DoS_soft/channel_switch/channel_switch_versions.h"
#include "suite/suite_helper.h"
#include "system/utils.h"

namespace wpa3_tester::suite::channel_switch_filler{
using namespace std;
using namespace filesystem;
using namespace nlohmann;

void generate_report(RunSuiteStatus &rss){ //TODO get versions
	log(LogLevel::INFO, "Generating channel_switch versions test suite report");

	const auto run_dir = rss.run_folder();
	if(!exists(run_dir)){
		log(LogLevel::ERROR, "Run folder not found: {}", run_dir.string());
		return;
	}

	// test_name, ap_driver, client_driver, attacker_driver, hostapd_version, passed
	vector<tuple<string, string, string, string, string, bool>> test_results;

	for(const auto &entry: directory_iterator(run_dir)){
		if(!entry.is_directory()) continue;

		const auto &test_folder = entry.path();
		const auto result = helper::load_result_json(test_folder);
		if(!result) continue;

		const bool passed     = result->value("passed", false);
		const string test_name = test_folder.filename().string();

		const auto drv = helper::load_test_drivers(test_folder);

		string hostapd_version = "?";
		const auto config_path = test_folder / "test_config.yaml";
		if(exists(config_path)){
			const auto cfg = YAML::LoadFile(config_path.string());
			if(cfg["actors"] && cfg["actors"]["access_point"]
				&& cfg["actors"]["access_point"]["setup"]
				&& cfg["actors"]["access_point"]["setup"]["program_config"]
				&& cfg["actors"]["access_point"]["setup"]["program_config"]["version"])
				hostapd_version = cfg["actors"]["access_point"]["setup"]["program_config"]["version"].as<string>();
		}

		test_results.emplace_back(test_name,
			helper::get_driver(drv, "access_point"),
			helper::get_driver(drv, "client"),
			helper::get_driver(drv, "attacker"),
			hostapd_version, passed);
	}

	auto report = helper::open_report(run_dir / "report.md");
	if(!report.is_open()) return;

	report << "# Channel Switch Versions Test Suite Report\n\n";
	report << "Summary of Channel Switch attack tests across different hostapd versions.\n\n";

	if(test_results.empty()){
		report << "No test results found.\n";
		report.close();
		return;
	}

	report << "## Test Results\n\n";
	report << "| Test | AP Driver | Client Driver | Attacker Driver | Hostapd Version | Result |\n";
	report << "|------|-----------|---------------|-----------------|-----------------|--------|\n";

	for(const auto &[test_name, ap_drv, cli_drv, att_drv, version, passed]: test_results){
		const string name_cell   = exists(run_dir / test_name / "report.md")
			? "[" + test_name + "](" + test_name + "/report.md)" : test_name;
		const string result_link = "[" + string(passed ? "PASSED" : "FAILED") + "](" + test_name + "/result.json)";
		report << "| " << name_cell << " | " << ap_drv << " | " << cli_drv << " | "
			   << att_drv << " | " << version << " | " << result_link << " |\n";
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
	log(LogLevel::INFO, "Channel switch versions report generated: {}", (run_dir / "report.md").string());
}
}