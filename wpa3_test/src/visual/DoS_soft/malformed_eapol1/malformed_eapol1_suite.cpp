#include <filesystem>
#include <nlohmann/json.hpp>

#include "suite/DoS_soft/malformed_eapol1/malformed_eapol1_suite.h"
#include "default.h"
#include "config/RunSuiteStatus.h"
#include "ex_program/hostapd/hostapd_helper.h"
#include "logger/report.h"
#include "overview/html_utils.h"
#include "suite/result_helper.h"
#include "suite/suite_helper.h"

namespace wpa3_tester::suite::malformed_eapol1_filler{
using namespace std;
using namespace filesystem;
using namespace nlohmann;

MalformedEapol1TestEntry MalformedEapol1TestEntry::parse(const path &test_folder){
	auto e = helper::load_result_default<MalformedEapol1TestEntry>(test_folder);
	e.test_name = test_folder.filename().string();
	const auto rs = helper::load_test_rs(test_folder);

	const auto ap = rs->get_actor("ap");
	e.ap_mac = ap->get(SK::mac);
	e.ap_source = ap->get(SK::source);
	e.ap_driver = rs->get_actor("ap").get(SK::driver_name);

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


	//FIXME static paths
	e.sta_graph = test_folder / "observer" / "tshark" / "client_graph.png";
	e.ap_graph = test_folder / "observer" / "tshark" / "ap_graph.png";
	e.client_driver = rs->get_actor("client").get(SK::driver_name);
	e.client_version = hostapd::get_version(*rs, "client");
	e.attacker_driver = rs->get_actor("attacker").get(SK::driver_name);
	return e;
}

vector<MalformedEapol1TestEntry> MalformedEapol1TestEntry::collect_results(const path &test_data_dir) {
	auto entries = helper::get_results_default<MalformedEapol1TestEntry>(test_data_dir);

	ranges::sort(entries, [](const MalformedEapol1TestEntry& a, const MalformedEapol1TestEntry& b) {
		if (a.client_version != b.client_version){ return a.client_version < b.client_version;}
		if (a.client_mfp != b.client_mfp) {return a.client_mfp < b.client_mfp; }
		if (a.ap_driver != b.ap_driver){ return a.ap_driver < b.ap_driver;}
		if (a.attacker_driver != b.attacker_driver) { return a.attacker_driver < b.attacker_driver;}
		return false;
	});

	return entries;
}

void MalformedEapol1TestEntry::render_table(overview::HtmlGuard &f, const std::string &title,
	const path &suite_data_dir, const path &page_dir){

	helper::div_card<MalformedEapol1TestEntry>(f, title, suite_data_dir, [&](overview::HtmlGuard& hg,
		const std::vector<MalformedEapol1TestEntry>& entries) {

		HtmlPathTable t(hg, entries);

		#define COL(name, body) col(name, [&]( [[maybe_unused]] const auto& e) { hg << body; })
		t.build([&](auto col) {
			col("Test",				&MalformedEapol1TestEntry::test_name);
			COL("AP MAC (source)",  overview::device(e.ap_mac, page_dir) << " (" << e.ap_source << ")");
			COL("Client MAC (source)",      overview::device(e.client_mac, page_dir) << " (" << e.client_source << ")");
			col("Client wpa_supplicant version",	&MalformedEapol1TestEntry::client_version);
			COL("Disconnected? <br> (from AP view)", e.client_disconnected << " (" << e.ap_disconnected << ")");
			COL("Rogue WPA2 AP,same channel?\n(cracked)",	 e.rogue_ap_connected << " (" << e.cracked << ")");
			col("Client MFP",					&MalformedEapol1TestEntry::client_mfp);
			COL("AP/Client WPA support",		e.ap_WPA_support << "<br>" << e.client_WPA_support);
			col("Connected WPA version",		&MalformedEapol1TestEntry::conn_WPA_version);
		})->render({"Test"});
		#undef COL
	});
}

void MalformedEapol1TestEntry::generate_report(RunSuiteStatus &rss){
	const auto entries = helper::get_results_default<MalformedEapol1TestEntry>(rss.run_folder());

	const auto report_path =  rss.run_folder() / REPORT_NAME;
	report::ReportGuard report(rss.run_folder());
	if(!report) return;

	report << "# Malformed EAPOL-1 Test Suite Report\n\n";
	report << "Tests whether a malformed EAPOL Key frame (invalid tag length) causes client disconnection.\n\n";

	if(entries.empty()){ report << "No test results found.\n"; return; }

	report << "## Results\n\n";
	report << "| Test | AP Driver | Client Driver | Client Version | Attacker Driver | Disconnected (count) | Rogue AP | Graphs |\n";
	report << "|------|-----------|---------------|----------------|-----------------|:--------------------:|:--------:|:------:|\n";

	//int passed_count = 0;
	for(const auto &e: entries){
		//if(e.disconnect_count > 0) ++passed_count;

		string graphs;
		if(exists(e.sta_graph)) graphs += "[STA](" + e.sta_graph.string() + ")";
		if(exists(e.ap_graph)){
			if(!graphs.empty()) graphs += ' ';
			graphs += "[AP](" + e.ap_graph.string() + ")";
		}
		if(graphs.empty()) graphs = "-";

		const string disc_link = "[" + string((e.client_disconnected.value()) ? "yes" : "no") + "]"
			"(" + e.test_name + "/" + RESULT_NAME + ")";
		report << "| " << report::link(e.test_name , path(e.test_name) / REPORT_NAME) << " | "
			<< e.ap_driver << " | "
			<< e.client_driver << " | "
			<< e.client_version << " | "
			<< e.attacker_driver << " | "
			<< disc_link << " | "
			<< e.rogue_ap_connected << " | "
			<< graphs << " |\n";
	}
}
}
