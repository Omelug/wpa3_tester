#include <filesystem>
#include <fstream>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <yaml-cpp/yaml.h>

#include "suite/DoS_soft/channel_switch/channel_switch_versions.h"
#include "config/RunSuiteStatus.h"
#include "logger/log.h"
#include "suite/suite_helper.h"
#include "system/utils.h"

namespace wpa3_tester::suite::channel_switch_filler{
using namespace std;
using namespace filesystem;

CsaVersionTestEntry parse_test_folder(const path &test_folder){
	CsaVersionTestEntry e;
	e.name = test_folder.filename().string();

	if(const auto result = helper::load_result_json(test_folder))
		e.passed = result->value("passed", false);

	const auto rs      = helper::load_test_rs(test_folder);
	e.ap_driver        = rs->get_actor("access_point").get(SK::driver_name);
	e.client_driver    = rs->get_actor("client").get(SK::driver_name);
	e.attacker_driver  = rs->get_actor("attacker").get(SK::driver_name);
	e.rogue_ap_driver  = rs->get_actor("rogue_ap").get(SK::driver_name);

	const auto cfg_path = test_folder / "test_config.yaml";
	if(exists(cfg_path)){
		try{
			const auto cfg = YAML::LoadFile(cfg_path.string());
			if(cfg["name"])
				e.name = cfg["name"].as<string>();
			if(cfg["actors"] && cfg["actors"]["access_point"]
				&& cfg["actors"]["access_point"]["setup"]
				&& cfg["actors"]["access_point"]["setup"]["program_config"]
				&& cfg["actors"]["access_point"]["setup"]["program_config"]["version"])
				e.hostapd_version = cfg["actors"]["access_point"]["setup"]["program_config"]["version"].as<string>();
			if(cfg["actors"] && cfg["actors"]["client"]
				&& cfg["actors"]["client"]["setup"]
				&& cfg["actors"]["client"]["setup"]["program_config"]
				&& cfg["actors"]["client"]["setup"]["program_config"]["version"])
				e.supplicant_version = cfg["actors"]["client"]["setup"]["program_config"]["version"].as<string>();
			if(cfg["attack_config"]){
				if(cfg["attack_config"]["new_channel"])
					e.new_channel = to_string(cfg["attack_config"]["new_channel"].as<int>());
				if(cfg["attack_config"]["attack_time"])
					e.attack_time = to_string(cfg["attack_config"]["attack_time"].as<int>());
			}
		} catch(...){}
	}

	const path tshark = test_folder / "observer" / "tshark";
	if(const auto p = tshark / "client_graph.png";       exists(p)) e.client_graph = p;
	if(const auto p = tshark / "access_point_graph.png"; exists(p)) e.ap_graph     = p;

	return e;
}

void generate_report(RunSuiteStatus &rss){
	log(LogLevel::INFO, "Generating channel_switch versions test suite report");

	const auto run_dir = rss.run_folder();
	if(!exists(run_dir)){
		log(LogLevel::ERROR, "Run folder not found: {}", run_dir.string());
		return;
	}

	auto entries = helper::collect_entries_nested(run_dir, [](const path &p, const path &) {
		return parse_test_folder(p);
	});

	auto report = helper::open_report(run_dir / "report.md");
	if(!report.is_open()) return;

	report << "# Channel Switch Versions Test Suite Report\n\n";
	report << "Summary of Channel Switch attack tests across different hostapd versions.\n\n";

	if(entries.empty()){
		report << "No test results found.\n";
		report.close();
		return;
	}

	report << "## Test Results\n\n";
	report << "| Test | AP Driver | Client Driver | Attacker Driver | Hostapd Version | Result |\n";
	report << "|------|-----------|---------------|-----------------|-----------------|--------|\n";

	for(const auto &e: entries){
		const string name_cell   = exists(run_dir / e.name / "report.md")
			? "[" + e.name + "](" + e.name + "/report.md)" : e.name;
		const string result_link = "[" + string(e.passed.value() ? "PASSED" : "FAILED")
			+ "](" + e.name + "/result.json)";
		report << "| " << name_cell << " | " << e.ap_driver << " | " << e.client_driver
			   << " | " << e.attacker_driver << " | " << e.hostapd_version
			   << " | " << result_link << " |\n";
	}

	report << "\n## Summary\n\n";
	const size_t passed_count = ranges::count_if(entries, [](const auto &e){ return e.passed.value_or(false); });
	report << "- Total Tests: " << entries.size() << "\n";
	report << "- Passed: " << passed_count << "\n";
	report << "- Failed: " << (entries.size() - passed_count) << "\n";
	report << "- Success Rate: " << fixed << setprecision(1)
		   << (100.0 * passed_count / entries.size()) << "%\n";

	report.close();
	set_public_perms(run_dir / "report.md");
	log(LogLevel::INFO, "Channel switch versions report generated: {}", (run_dir / "report.md").string());
}
}
