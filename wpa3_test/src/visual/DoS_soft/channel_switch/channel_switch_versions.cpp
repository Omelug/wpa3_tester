#include <filesystem>
#include <yaml-cpp/yaml.h>

#include "visual/DoS_soft/channel_switch/channel_switch_versions.h"

#include "config/RunSuiteStatus.h"
#include "default.h"
#include "logger/report.h"
#include "visual/result_helper.h"
#include "visual/suite_helper.h"

namespace wpa3_tester::visual::channel_switch_filler {
using namespace std;
using namespace filesystem;

CsaVersionTestEntry CsaVersionTestEntry::parse(const path &test_folder) {
	auto e = helper::load_result_default<CsaVersionTestEntry>(test_folder);
	e.name = test_folder.filename().string();

	const auto rs = helper::load_test_rs(test_folder);
	e.ap_driver = rs->get_actor("ap").get(SK::driver_name);
	e.client_driver = rs->get_actor("client").get(SK::driver_name);
	e.attacker_driver = rs->get_actor("attacker").get(SK::driver_name);
	e.rogue_ap_driver = rs->get_actor("rogue_ap").get(SK::driver_name);

	e.hostapd_version = hostapd::get_version(*rs, "ap");
	e.supplicant_version = hostapd::get_version(*rs, "client");

	const auto cfg_path = test_folder / TEST_CONFIG_NAME;
	if(exists(cfg_path)) {
		const auto cfg = YAML::LoadFile(cfg_path.string());
		e.name = cfg["name"].as<string>();
		e.new_channel = to_string(cfg["attack_config"]["new_channel"].as<int>());
		e.attack_time = to_string(cfg["attack_config"]["attack_time"].as<int>());

	}

	const path tshark = test_folder / "observer" / "tshark";
	if(const auto p = tshark / "client_graph.png"; exists(p)) e.client_graph = p;
	if(const auto p = tshark / "ap_graph.png"; exists(p)) e.ap_graph = p;
	return e;
}

void CsaVersionTestEntry::generate_report(RunSuiteStatus &rss) {
	const auto run_dir = rss.run_folder();
	const auto entries = helper::get_results_default<CsaVersionTestEntry>(run_dir);

	report::ReportGuard report(run_dir);
	if(!report) return;

	report << "# Channel Switch Versions Test Suite Report\n\n";
	report << "Summary of Channel Switch attack tests across different hostapd versions.\n\n";

	if(entries.empty()) {
		report << "No test results found.\n";
		return;
	}

	report << "## Test Results\n\n";
	report << "| Test | AP Driver | Client Driver | Attacker Driver | Hostapd Version | Result |\n";
	report << "|------|-----------|---------------|-----------------|-----------------|--------|\n";

	for(const auto &e: entries) {

		//const string result_link = "[" + string(e.passed.value() ? "PASSED" : "FAILED") + "](" + e.name + "/" +
		//		RESULT_NAME + ")";
		report << "| " << report::link(e.name, path(e.name) / REPORT_NAME) << " | " << e.ap_driver << " | "
			   << e.client_driver << " | " << e.attacker_driver << " | " << e.hostapd_version << /*" | "
			<< result_link*/
				"" << " |\n";
	}
}
}
