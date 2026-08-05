#include "suite/DoS_soft/channel_switch/channel_switch_rogueAP.h"
#include <filesystem>
#include "default.h"
#include "config/RunStatus.h"
#include "config/RunSuiteStatus.h"
#include "logger/log_util.h"
#include "logger/report.h"
#include "overview/html_guard.h"
#include "overview/html_utils.h"
#include "suite/result_helper.h"
#include "suite/suite_helper.h"

namespace wpa3_tester::suite::channel_switch_rogueAP{
using namespace std;
using namespace filesystem;

CsaTestEntry CsaTestEntry::parse(const path &test_folder){
	auto e = helper::load_result_default<CsaTestEntry>(test_folder);
	e.name = test_folder.filename().string();

	const auto cfg_path = test_folder / TEST_CONFIG_NAME;
	const auto rs = helper::load_test_rs(test_folder); //FIXME error on corrupted test, stop (checkall load_test_rs)
	const auto ap = rs->get_actor("ap");
	e.ap_mac = ap->get(SK::mac);
	e.ap_source = ap->get(SK::source);

	const auto client = rs->get_actor("client");
	//FIXME add mac to config/mapping to get it here in report (if client is external)
	e.client_mac = client->get(SK::mac);
	e.client_source = client->get(SK::source);
	e.client_driver = client[SK::driver_name];

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

vector<CsaTestEntry> CsaTestEntry::collect_results(const path &test_data_dir) {

	auto entries = helper::collect_entries_nested(test_data_dir, [&test_data_dir](const path &p){
		auto e = parse(p);
		e.rel_path = relative(p, test_data_dir);
		return e;
	});

	ranges::sort(entries, [](const CsaTestEntry& a, const CsaTestEntry& b) {
		const string sta_mac_a = a.client_mac;
		const string sta_mac_b = b.client_mac;
		if (sta_mac_a != sta_mac_b) return sta_mac_a < sta_mac_b;

		auto opt_rank = [](const optional<bool>& v) -> int {
		   return v.has_value() ? (*v ? 0 : 1) : 2;
		};
		//if (a.rel_path != b.rel_path) return a.rel_path < b.rel_path;

		const int ocv_a = opt_rank(a.ap_ocv.value()) + finite(opt_rank(a.client_ocv.value()));
		const int ocv_b = opt_rank(b.ap_ocv.value()) + opt_rank(b.client_ocv.value());
		if (ocv_a != ocv_b) return ocv_a < ocv_b;

		const int disc_a = opt_rank(a.client_disconnected.value());
		const int disc_b = opt_rank(b.client_disconnected.value());
		if (disc_a != disc_b) return disc_a < disc_b;

		return opt_rank(a.rogue_ap_connected) < opt_rank(b.rogue_ap_connected);
	});

	return entries;
}

void CsaTestEntry::render_table(overview::HtmlGuard &f, const string &title,
	const path &suite_data_dir, const path &page_dir){

	helper::div_card<CsaTestEntry>(f, title, suite_data_dir, [&](overview::HtmlGuard& hg,
		const std::vector<CsaTestEntry>& entries) {

		HtmlPathTable t(hg, entries);

		#define COL(name, body) col(name, [&]([[maybe_unused]] const auto& e) { f << body; })
		t.build([&](auto col) {
			COL("Test",                     overview::test_name_cell(e.rel_path, e.name, page_dir));
			COL("AP MAC (source)",          overview::device(e.ap_mac, page_dir) << " (" << e.ap_source << ")");
			COL("Client MAC (source)",      overview::device(e.client_mac, page_dir) << " (" << e.client_source << ")");
			COL("Attacker (driver)<br> RogueAP MAC (driver)",
				overview::device(e.attacker_mac, page_dir) << " (" << e.attacker_driver << ")<br>"
				<< overview::device(e.rogue_ap_mac, page_dir) << " (" << e.rogue_ap_driver << ")";
				);
			COL("Disconnected? <br> (from AP view)", e.client_disconnected << " (" << e.ap_disconnected << ")");
			col("Rogue WPA2 AP?",				&CsaTestEntry::rogue_ap_connected);
			COL("AP OCV / Client OCV support",	e.ap_ocv << "<br>" << e.client_ocv );
			col("Client MFP",					&CsaTestEntry::client_mfp);
			COL("AP/Client WPA support",		e.ap_WPA_support << "<br>" << e.client_WPA_support);
			col("Connected WPA version",		&CsaTestEntry::conn_WPA_version);
			col("client scanning",				&CsaTestEntry::client_scanning);
		})->render();
		#undef COL
	});
}

void CsaTestEntry::generate_report(RunSuiteStatus &rss){
	const auto run_dir = rss.run_folder();
	const auto entries = helper::collect_entries_nested(run_dir, [&run_dir](const path &p){
		auto e = parse(p);
		e.rel_path = relative(p, run_dir);
		return e;
	});

	report::ReportGuard report(run_dir);
	if(!report) return;

	report << "# CSA Rogue AP Test Suite Report\n\n";
	report << "Summary of Channel Switch + Rogue AP downgrade attack tests.\n\n";

	if(entries.empty()){
		report << "No test results found.\n";
		return;
	}

	report << "## Test Results\n\n";
	report <<
			"| Test | AP MAC (source) | Client MAC (source) | Attacker MAC (driver) | Disconnected? (from_AP_view) ? | Rogue AP? | AP OCV / Client OCV | Client MFP | Result |\n";
	report <<
			"|------|-----------------|---------------------|-----------------------|--------------------------------|-----------|---------------------|------------|--------|\n";

	for(const auto &e: entries){
		string attacker_cell = e.attacker_mac + " (" + e.attacker_driver + ")";
		if(!e.rogue_ap_mac.empty() || !e.rogue_ap_driver.empty())
			attacker_cell += "<br>" + e.rogue_ap_mac + " (" + e.
					rogue_ap_driver + ")";
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
