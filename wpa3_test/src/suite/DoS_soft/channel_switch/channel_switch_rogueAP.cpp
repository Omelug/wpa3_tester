#include <filesystem>
#include <iomanip>

#include "suite/DoS_soft/channel_switch/channel_switch_rogueAP.h"
#include "default.h"
#include "config/RunStatus.h"
#include "config/RunSuiteStatus.h"
#include "ex_program/hostapd/hostapd_helper.h"
#include "logger/report.h"
#include "suite/result_helper.h"
#include "suite/suite_helper.h"

namespace wpa3_tester::suite::channel_switch_rogueAP{
using namespace std;
using namespace filesystem;

CsaTestEntry parse_test_folder(const path &test_folder){
	auto e = helper::load_result_default<CsaTestEntry>(test_folder);
	e.name = test_folder.filename().string();

	const auto cfg_path = test_folder / TEST_CONFIG_NAME;
	if(exists(cfg_path)){
		RunStatus rs{};
		rs.config_path(absolute(cfg_path));
		rs.config(RunStatus::config_validation(rs.config_path()));
		rs.run_folder(test_folder);
		rs.load_actor_interface_mapping();

		const auto ap = rs.get_actor("access_point");
		e.ap_mac = ap->get(SK::mac);
		e.ap_source = ap->get(SK::source);
		e.ap_ocv = hostapd::get_okc(rs, "access_point");

		const auto client = rs.get_actor("client");
		e.client_mac = client->get(SK::mac);
		e.client_source = client->get(SK::source);
		e.client_ocv =  hostapd::get_ocv(rs, "client");
		e.client_mfp = hostapd::get_mfp_from_supplicant(test_folder / "client_wpa_supplicant.conf");

		const auto att = rs.get_actor("attacker");
		e.attacker_mac = att->get(SK::mac);
		e.attacker_driver = att->get(SK::driver_name);

		if(const auto rogue = rs.actor("attacker")){
			e.rogue_ap_mac = rogue->get(SK::mac);
			e.rogue_ap_driver = rogue->get(SK::driver_name);
		}
	}

	const path tshark = test_folder / "observer" / "tshark";
	if(const auto p = tshark / "client_graph.png"; exists(p)) e.client_graph = p;
	if(const auto p = tshark / "access_point_graph.png"; exists(p)) e.ap_graph = p;

	return e;
}

void generate_report(RunSuiteStatus &rss){
	const auto run_dir = rss.run_folder();
	const auto entries = helper::collect_entries_nested(run_dir, [&run_dir](const path &p){
		auto e = parse_test_folder(p);
		e.rel_path = relative(p, run_dir);
		return e;
	});

	report::ReportGuard report(run_dir);
	if(!report) return;

	report << "# CSA Rogue AP Test Suite Report\n\n";
	report << "Summary of Channel Switch + Rogue AP downgrade attack tests.\n\n";

	if(entries.empty()){ report << "No test results found.\n"; return; }

	report << "## Test Results\n\n";
	report << "| Test | AP MAC (source) | Client MAC (source) | Attacker MAC (driver) | Disconnected? (from_AP_view) ? | Rogue AP? | AP OCV / Client OCV | Client MFP | Result |\n";
	report << "|------|-----------------|---------------------|-----------------------|--------------------------------|-----------|---------------------|------------|--------|\n";

	for(const auto &e: entries){
		const string rel = e.rel_path.string();
		const string name_cell = exists(run_dir / e.rel_path / REPORT_NAME)
								? "[" + e.name + "](" + rel + "/" + REPORT_NAME + ")"
								: e.name;
		const string result_link = "[" + string(e.rogue_ap_connected.value() ? "PASSED" : "FAILED") + "](" + rel + "/" +
				RESULT_NAME + ")";
		const string ap_cell = e.ap_mac + " (" + e.ap_source + ")";
		const string client_cell = e.client_mac + " (" + e.client_source + ")";
		string attacker_cell = e.attacker_mac + " (" + e.attacker_driver + ")";
		if(!e.rogue_ap_mac.empty() || !e.rogue_ap_driver.empty())
			attacker_cell += "<br>" + e.rogue_ap_mac + " (" + e.rogue_ap_driver + ")";

		report << "| " << name_cell << " | "
			<< ap_cell << " | "
			<< client_cell << " | "
			<< attacker_cell << " | "
			<< e.disconnected << " (" << e.ap_disconnected << ")" << " | "
			<< e.rogue_ap_connected << " | "
			<< e.ap_ocv << " / " << e.client_ocv << " | "
			<< e.client_mfp << " | "
			<< result_link << " |\n";
	}

	report << "\n## Summary\n\n";
	const size_t passed_count = ranges::count_if(entries, [](const auto &e){ return e.rogue_ap_connected.value_or(false); });
	report << "- Total Tests: " << entries.size() << "\n";
	report << "- Passed: " << passed_count << "\n";
	report << "- Failed: " << (entries.size() - passed_count) << "\n";
	report << "- Success Rate: " << fixed << setprecision(1) << (100.0 * passed_count / entries.size()) << "%\n";
}
}
