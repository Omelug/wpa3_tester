#include <filesystem>
#include <nlohmann/json.hpp>

#include "visual/downgrade/owe_trans_filler.h"
#include "default.h"
#include "config/RunSuiteStatus.h"
#include "logger/report.h"
#include "overview/html_guard.h"
#include "overview/html_utils.h"
#include "visual/result_helper.h"
#include "visual/suite_helper.h"

namespace wpa3_tester::visual::owe_trans_filler{
using namespace std;
using namespace filesystem;
using namespace nlohmann;

OweTransTestEntry OweTransTestEntry::parse(const path &test_folder){
	auto e = helper::load_result_default<OweTransTestEntry>(test_folder);
	e.test_folder  = test_folder;
	e.test_name = test_folder.filename().string();

	const auto rs = helper::load_test_rs(test_folder);
	e.ap_driver = rs->get_actor("ap").get(SK::driver_name);
	e.client_driver = rs->get_actor("client").get(SK::driver_name);
	e.attacker_driver = rs->get_actor("attacker").get(SK::driver_name);
	return e;
}

void OweTransTestEntry::render_table(overview::HtmlGuard &f, const string &title,
	const path &suite_data_dir, const path &){

	helper::div_card<OweTransTestEntry>(f, title, suite_data_dir, [&](overview::HtmlGuard& hg,
		const std::vector<OweTransTestEntry>& entries) {
		HtmlPathTable t(f, entries);

		#define COL(name, body) col(name, [&]( [[maybe_unused]] const auto& e) { hg << body; })

		t.build([&](auto col) {
			//COL("Test",                 overview::test_name_cell(e.folder, e.test_name, page_dir));
			col("AP Driver",            &OweTransTestEntry::ap_driver);
			col("Client Driver",        &OweTransTestEntry::client_driver);
			col("Attacker Driver",      &OweTransTestEntry::attacker_driver);
			col("BC probes",            &OweTransTestEntry::broadcast_probe_count);
			col("SSID probes",          &OweTransTestEntry::ssid_probe_count);
			col("Disconnected",         &OweTransTestEntry::disconnected);
			COL("Vulnerable",           (e.ssid_probe_count > 0));
		})->render();
		#undef COL
	});
}

void generate_report(RunSuiteStatus &rss){
	const auto run_dir = rss.run_folder();
	const auto entries = helper::get_results_default<OweTransTestEntry>(run_dir);

	report::ReportGuard report(run_dir);
	if(!report) return;

	report << "# OWE Transition Probe Leak Test Suite Report\n\n";
	report << "Tests whether a client leaks probe requests after disconnection from an OWE AP.\n\n";

	if(entries.empty()){ report << "No test results found.\n"; return; }

	report << "## Test Results\n\n";
	report << "| Test | AP Driver | Client Driver | Attacker Driver | BC probes | SSID probes | Disconnected | Vulnerable |\n";
	report << "|------|-----------|---------------|-----------------|:---------:|:-----------:|:------------:|:----------:|\n";

	for(const auto &e: entries){
		const bool vuln = e.ssid_probe_count > 0;
		const string vuln_link = "[" + string(vuln ? "yes" : "no") + "](" + e.test_name + "/" + RESULT_NAME + ")";

		report << "| " << report::link(e.test_name, path(e.test_name) / REPORT_NAME) << " | "
			<< e.ap_driver << " | "
			<< e.client_driver << " | "
			<< e.attacker_driver << " | "
			<< e.broadcast_probe_count << " | "
			<< e.ssid_probe_count << " | "
			<< e.disconnected << " | "
			<< vuln_link << " |\n";
	}
}
}