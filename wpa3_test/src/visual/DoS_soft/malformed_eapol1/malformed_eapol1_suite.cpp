#include <filesystem>
#include <nlohmann/json.hpp>

#include "default.h"
#include "suite/DoS_soft/malformed_eapol1/malformed_eapol1_suite.h"
#include "config/RunSuiteStatus.h"
#include "logger/report.h"
#include "suite/result_helper.h"
#include "suite/suite_helper.h"
#include "ex_program/hostapd/hostapd_helper.h"
#include "overview/html_utils.h"

namespace wpa3_tester::suite::malformed_eapol1_filler{
using namespace std;
using namespace filesystem;
using namespace nlohmann;

MalformedEapol1TestEntry MalformedEapol1TestEntry::parse(const path &test_folder){
	auto e = helper::load_result_default<MalformedEapol1TestEntry>(test_folder);
	e.test_name = test_folder.filename().string();
	const auto rs = helper::load_test_rs(test_folder);
	//FIXME static paths
	e.sta_graph = test_folder / "observer" / "tshark" / "client_graph.png";
	e.ap_graph = test_folder / "observer" / "tshark" / "ap_graph.png";
	e.ap_driver = rs->get_actor("ap").get(SK::driver_name);
	e.client_driver = rs->get_actor("client").get(SK::driver_name);
	e.client_version = hostapd::get_version(*rs, "client");
	e.attacker_driver = rs->get_actor("attacker").get(SK::driver_name);
	return e;
}

void MalformedEapol1TestEntry::render_table(overview::HtmlGuard &f, const std::string &title,
	const path &suite_data_dir, const path &){
	helper::div_card<MalformedEapol1TestEntry>(f, title, suite_data_dir, [&](overview::HtmlGuard& hg,
			const std::vector<MalformedEapol1TestEntry>& entries) {

			HtmlPathTable t(hg, entries);

			#define COL(name, body) col(name, [&]( [[maybe_unused]] const auto& e) { hg << body; })

			t.build([&](auto col) {
				col("Test",				&MalformedEapol1TestEntry::test_name);
				col("AP driver",		&MalformedEapol1TestEntry::ap_driver);
				col("Client Driver",	&MalformedEapol1TestEntry::client_driver);
				col("Client wpa_supplicant version",	&MalformedEapol1TestEntry::client_version);
				col("Attacker driver",	&MalformedEapol1TestEntry::attacker_driver);
				COL("Disconnected? (count)",	(e.disconnect_count > 0) << " (" << e.disconnect_count << ")");
				col("Rogue AP?",        &MalformedEapol1TestEntry::rogue_ap_connected);
			})->render();
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
			if(!graphs.empty()) graphs += " ";
			graphs += "[AP](" + e.ap_graph.string() + ")";
		}
		if(graphs.empty()) graphs = "-";

		const string disc_link = "[" + string((e.disconnect_count > 0) ? "yes" : "no") + "]"
			"(" + e.test_name + "/" + RESULT_NAME + ")";
		report << "| " << report::link(e.test_name , path(e.test_name) / REPORT_NAME) << " | "
			<< e.ap_driver << " | "
			<< e.client_driver << " | "
			<< e.client_version << " | "
			<< e.attacker_driver << " | "
			<< disc_link << "(" << e.disconnect_count << ")" << " | "
			<< e.rogue_ap_connected << " | "
			<< graphs << " |\n";
	}
}
}
