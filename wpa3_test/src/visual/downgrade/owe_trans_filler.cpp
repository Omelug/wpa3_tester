#include <filesystem>
#include <nlohmann/json.hpp>

#include "suite/downgrade/owe_trans_filler.h"
#include "default.h"
#include "config/RunSuiteStatus.h"
#include "logger/report.h"
#include "overview/html_guard.h"
#include "suite/result_helper.h"
#include "suite/suite_helper.h"

namespace wpa3_tester::suite::owe_trans_filler{
using namespace std;
using namespace filesystem;
using namespace nlohmann;

OweTransTestEntry OweTransTestEntry::parse(const path &test_folder){
	auto e = helper::load_result_default<OweTransTestEntry>(test_folder);
	e.test_name = test_folder.filename().string();

	const auto rs = helper::load_test_rs(test_folder);
	e.ap_driver = rs->get_actor("access_point").get(SK::driver_name);
	e.client_driver = rs->get_actor("client").get(SK::driver_name);
	e.attacker_driver = rs->get_actor("attacker").get(SK::driver_name);
	return e;
}

void OweTransTestEntry::render_table(overview::HtmlGuard &f,
                                     const vector<path> &folders,
                                     const path &page_dir){
	f << "        <table class=\"aggregate\">\n"
	  << "            <thead><tr>"
	  << "<th>Test</th><th>AP Driver</th><th>Client Driver</th><th>Attacker Driver</th>"
	  << "<th>BC probes</th><th>SSID probes</th><th>Disconnected</th><th>Vulnerable</th>"
	  << "</tr></thead>\n            <tbody>\n";
	for(const auto &p : folders){
		const auto e = parse(p);
		const bool vuln = e.ssid_probe_count > 0;
		f << "                <tr>\n"
		  << "                    <td>" << overview::test_name_cell(p, e.test_name, page_dir) << "</td>\n"
		  << "                    <td>" << e.ap_driver << "</td>\n"
		  << "                    <td>" << e.client_driver << "</td>\n"
		  << "                    <td>" << e.attacker_driver << "</td>\n"
		  << "                    <td>" << e.broadcast_probe_count << "</td>\n"
		  << "                    <td>" << e.ssid_probe_count << "</td>\n"
		  << "                    <td>" << e.disconnected << "</td>\n"
		  << "                    <td>" << vuln << "</td>\n"
		  << "                </tr>\n";
	}
	f << "            </tbody>\n        </table>\n";
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