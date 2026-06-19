#include <filesystem>
#include <fstream>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <yaml-cpp/yaml.h>

#include "suite/DoS_soft/channel_switch/channel_switch_versions.h"

#include "default.h"
#include "config/RunSuiteStatus.h"
#include "suite/result_helper.h"
#include "suite/suite_helper.h"

namespace wpa3_tester::suite::channel_switch_filler{
using namespace std;
using namespace filesystem;

CsaVersionTestEntry parse_test_folder(const path &test_folder){
	auto e = helper::load_result_default<CsaVersionTestEntry>(test_folder);
	e.name = test_folder.filename().string();

	const auto rs = helper::load_test_rs(test_folder);
	e.ap_driver = rs->get_actor("access_point").get(SK::driver_name);
	e.client_driver = rs->get_actor("client").get(SK::driver_name);
	e.attacker_driver = rs->get_actor("attacker").get(SK::driver_name);
	e.rogue_ap_driver = rs->get_actor("rogue_ap").get(SK::driver_name);

	const auto cfg_path = test_folder / TEST_CONFIG_NAME;
	if(exists(cfg_path)){
		try{
			const auto cfg = YAML::LoadFile(cfg_path.string());
			if(cfg["name"]) e.name = cfg["name"].as<string>();
			if(cfg["actors"] && cfg["actors"]["access_point"] && cfg["actors"]["access_point"]["setup"] && cfg["actors"]
				["access_point"]["setup"]["program_config"] && cfg["actors"]["access_point"]["setup"]["program_config"][
					"version"]) e.hostapd_version = cfg["actors"]["access_point"]["setup"]["program_config"]["version"].
					as<string>();
			if(cfg["actors"] && cfg["actors"]["client"] && cfg["actors"]["client"]["setup"] && cfg["actors"]["client"][
				"setup"]["program_config"] && cfg["actors"]["client"]["setup"]["program_config"]["version"]) e.
					supplicant_version = cfg["actors"]["client"]["setup"]["program_config"]["version"].as<string>();
			if(cfg["attack_config"]){
				if(cfg["attack_config"]["new_channel"]) e.new_channel = to_string(
					cfg["attack_config"]["new_channel"].as<int>());
				if(cfg["attack_config"]["attack_time"]) e.attack_time = to_string(
					cfg["attack_config"]["attack_time"].as<int>());
			}
		} catch(...){}
	}

	const path tshark = test_folder / "observer" / "tshark";
	if(const auto p = tshark / "client_graph.png"; exists(p)) e.client_graph = p;
	if(const auto p = tshark / "access_point_graph.png"; exists(p)) e.ap_graph = p;
	return e;
}

void generate_report(RunSuiteStatus &rss){
	const auto run_dir = rss.run_folder();
	const auto entries = helper::collect_entries_nested(run_dir, [](const path &p){
		return parse_test_folder(p);
	});

	helper::ReportGuard report(run_dir);
	if(!report) return;

	report << "# Channel Switch Versions Test Suite Report\n\n";
	report << "Summary of Channel Switch attack tests across different hostapd versions.\n\n";

	if(entries.empty()){ report << "No test results found.\n"; return; }

	report << "## Test Results\n\n";
	report << "| Test | AP Driver | Client Driver | Attacker Driver | Hostapd Version | Result |\n";
	report << "|------|-----------|---------------|-----------------|-----------------|--------|\n";

	for(const auto &e: entries){
		const string name_cell = exists(run_dir / e.name / REPORT_NAME)
								? "[" + e.name + "](" + e.name + "/" + REPORT_NAME + ")"
								: e.name;
		//const string result_link = "[" + string(e.passed.value() ? "PASSED" : "FAILED") + "](" + e.name + "/" +
		//		RESULT_NAME + ")";
		report << "| " << name_cell << " | " << e.ap_driver << " | " << e.client_driver << " | " <<
				e.attacker_driver << " | " << e.hostapd_version << " | " << /*result_link*/ "" << " |\n";
	}

	/*report << "\n## Summary\n\n";
	const size_t passed_count = ranges::count_if(entries, [](const auto &e){ return e.passed; });
	report << "- Total Tests: " << entries.size() << "\n";
	report << "- Passed: " << passed_count << "\n";
	report << "- Failed: " << (entries.size() - passed_count) << "\n";
	report << "- Success Rate: " << fixed << setprecision(1) << (100.0 * passed_count / entries.size()) << "%\n";
	*/
}
}
