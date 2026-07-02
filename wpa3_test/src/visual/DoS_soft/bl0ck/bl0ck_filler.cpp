#include <filesystem>
#include <iomanip>
#include <yaml-cpp/yaml.h>

#include "default.h"
#include "config/RunStatus.h"
#include "config/RunSuiteStatus.h"
#include "logger/log.h"
#include "logger/report.h"
#include "overview/html_guard.h"
#include "suite/result_helper.h"
#include "suite/suite_helper.h"
#include "suite/DoS_soft/bl0ck/bl0ck_test_suites.h"

namespace wpa3_tester::suite::bl0ck_test_suites{
using namespace std;
using namespace filesystem;
using namespace nlohmann;

Bl0ckTestEntry Bl0ckTestEntry::parse(const path &test_folder){
	auto e = helper::load_result_default<Bl0ckTestEntry>(test_folder);
	e.name = test_folder.filename().string();

	const auto cfg_path = test_folder / TEST_CONFIG_NAME;
	if(exists(cfg_path)){
		RunStatus rs{};
		rs.config_path(cfg_path);
		rs.run_folder(test_folder);
		rs.load_actor_interface_mapping();

		const auto ap = rs.get_actor("access_point");
		e.ap_mac = ap->get(SK::mac);
		e.ap_source = ap->get(SK::source);

		const auto client = rs.get_actor("client");
		e.client_mac = client->get(SK::mac);
		e.client_source = client->get(SK::source);

		const auto att = rs.get_actor("attacker");
		e.attacker_mac = att->get(SK::mac);
		e.attacker_driver = att->get(SK::driver_name);

		const auto cfg = YAML::LoadFile(cfg_path);
		if(cfg["attack_config"] && cfg["attack_config"]["attack_variant"])
			e.attack_variant = cfg["attack_config"]["attack_variant"].as<string>();
	}

	return e;
}

void Bl0ckTestEntry::render_table(overview::HtmlGuard &f,
                                   const vector<path> &folders,
                                   const path &page_dir) {
	f << "        <table class=\"aggregate\">\n"
	  << "            <thead><tr>"
	  << "<th>Test</th><th>AP MAC (source)</th><th>Client MAC (source)</th>"
	  << "<th>Attacker (driver)</th><th>Variant</th><th>Disconnected?</th>"
	  << "</tr></thead>\n            <tbody>\n";
	for (const auto &p : folders) {
		const auto e = parse(p);
		f << "                <tr>\n"
		  << "                    <td>" << overview::test_name_cell(p, e.name, page_dir) << "</td>\n"
		  << "                    <td>" << overview::device(e.ap_mac, page_dir) << " (" << e.ap_source << ")</td>\n"
		  << "                    <td>" << overview::device(e.client_mac, page_dir) << " (" << e.client_source << ")</td>\n"
		  << "                    <td>" << overview::device(e.attacker_mac, page_dir) << " (" << e.attacker_driver << ")</td>\n"
		  << "                    <td>" << e.attack_variant << "</td>\n"
		  << "                    <td>" << (e.disconnect_count > 0) << "</td>\n"
		  << "                </tr>\n";
	}
	f << "            </tbody>\n        </table>\n";
}

void generate_bl0ck_mac_gen_report(RunSuiteStatus &rss){
	log(LogLevel::INFO, "Generating bl0ck mac_gen test suite report");
	auto run_dir = rss.run_folder();
	auto entries = helper::get_results_default<Bl0ckTestEntry>(run_dir);
	report::ReportGuard report(run_dir);
	if(!report) return;

	report << "# Bl0ck MAC Generator Test Suite Report\n\n";
	report << "Summary of Bl0ck attack tests across different driver combinations.\n\n";

	if(entries.empty()){
		report << "No test results found.\n";
		return;
	}

	report << "## Test Results\n\n";
	report << "| Test | AP MAC | Client MAC | Attacker (driver) | Variant | Result |\n";
	report << "|------|--------|------------|-------------------|---------|--------|\n";

	size_t passed_count = 0;
	for(const auto &e: entries){
		const string result_link = "[" + string((e.disconnect_count > 0) ? "PASSED" : "FAILED") + "](" + e.name + "/" +
				RESULT_NAME + ")";
		report << "| " << report::link(e.name , path(e.name) / REPORT_NAME) << " | "
			<< e.ap_mac << " | "
			<< e.client_mac << " | "
			<< e.attacker_mac << " (" << e.attacker_driver << ") | "
			<< e.attack_variant << " | "
			<< result_link << " |\n";
	}

	report << "\n## Summary\n\n";
	report << "- Total Tests: " << entries.size() << "\n";
	report << "- Passed: " << passed_count << "\n";
	report << "- Failed: " << (entries.size() - passed_count) << "\n";
	report << "- Success Rate: " << fixed << setprecision(1) << (100.0 * passed_count / entries.size()) << "%\n";

}
}
