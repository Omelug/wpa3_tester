#include "suite/DoS_soft/channel_switch/channel_switch_rogueAP.h"
#include <filesystem>
#include "default.h"
#include "config/RunStatus.h"
#include "config/RunSuiteStatus.h"
#include "logger/log_util.h"
#include "logger/report.h"
#include "overview/html_guard.h"
#include "suite/result_helper.h"
#include "suite/suite_helper.h"

namespace wpa3_tester::suite::channel_switch_rogueAP{
using namespace std;
using namespace filesystem;

CsaTestEntry parse_test_folder(const path &test_folder){
	auto e = helper::load_result_default<CsaTestEntry>(test_folder);
	e.name = test_folder.filename().string();

	const auto cfg_path = test_folder / TEST_CONFIG_NAME;
	const auto rs = helper::load_test_rs(test_folder); //FIXME error on currupted test, stop (checkall load_test_rs)
	const auto ap = rs->get_actor("ap");
	e.ap_mac = ap->get(SK::mac);
	e.ap_source = ap->get(SK::source);

	const auto client = rs->get_actor("client");
	//FIXME add mac to config/mapping to get it here in report (if client is external)
	e.client_mac = client->get(SK::mac);
	e.client_source = client->get(SK::source);

	const auto att = rs->get_actor("attacker");
	e.attacker_mac = att->get(SK::mac);
	e.attacker_driver = att->get(SK::driver_name);

	if(const auto rogue = rs->actor("rogue_ap")){ //optional
		e.rogue_ap_mac = rogue->get(SK::mac);
		e.rogue_ap_driver = rogue->get(SK::driver_name);
	}

	//const path tshark = test_folder / "observer" / "tshark";
	//if(const auto p = tshark / "client_graph.png"; exists(p)) e.client_graph = p;
	//if(const auto p = tshark / "ap_graph.png"; exists(p)) e.ap_graph = p;

	return e;
}

void render_table(overview::HtmlGuard &f, const vector<path> &folders, const path &page_dir) {
	f << "        <table class=\"aggregate\">\n"
	  << "            <thead><tr>"
	  << "<th>Test</th><th>AP MAC (source)</th><th>Client MAC (source)</th>"
	  << "<th>Attacker (driver)</th>"
	  << "<th>Disconnected?</th>"
	  << "<th>Rogue AP?</th>"
	  << "<th>Client MFP</th>"
	  << "<th>Scanning</th>"
	  << "</tr></thead>\n            <tbody>\n";
	for (const auto &p : folders) {
		const auto e = parse_test_folder(p);
		f << "                <tr>\n"
		  << "                    <td>" << overview::test_name_cell(p, e.name, page_dir) << "</td>\n"
		  << "                    <td>" << overview::device(e.ap_mac, page_dir) << " (" << e.ap_source << ")</td>\n"
		  << "                    <td>" << overview::device(e.client_mac, page_dir) << " (" << e.client_source << ")</td>\n"
		  << "                    <td>" << overview::device(e.attacker_mac, page_dir) << " (" << e.attacker_driver << ")</td>\n"
		  << "                    <td>" << e.client_disconnected << "</td>\n"
		  << "                    <td>" << e.rogue_ap_connected << "</td>\n"
		  << "                    <td>" << e.client_mfp << "</td>\n"
		  << "                    <td>" << e.client_scanning << "</td>\n"
		  << "                </tr>\n";
	}
	f << "            </tbody>\n        </table>\n";
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
		string attacker_cell = e.attacker_mac + " (" + e.attacker_driver + ")";
		if(!e.rogue_ap_mac.empty() || !e.rogue_ap_driver.empty())
			attacker_cell += "<br>" + e.rogue_ap_mac + " (" + e.rogue_ap_driver + ")";
		const string result_text = e.rogue_ap_connected ? (*e.rogue_ap_connected ? "PASSED" : "FAILED") : "N/A";

		report << "| " << report::link(e.name, e.rel_path / REPORT_NAME) << " | "
			<< e.ap_mac << " (" << e.ap_source << ") | "
			<< e.client_mac << " (" << e.client_source << ") | "
			<< attacker_cell << " | "
			<< e.client_disconnected << " (" << e.ap_disconnected << ") | "
			<< e.rogue_ap_connected << " | "
			<< e.ap_ocv << " / " << e.client_ocv << " | "
			<< e.client_mfp << " | "
			<< report::link(result_text, e.rel_path / RESULT_NAME) << " |\n";
	}

}
}
