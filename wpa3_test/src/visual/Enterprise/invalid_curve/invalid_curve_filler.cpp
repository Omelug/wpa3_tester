#include <filesystem>
#include <iomanip>
#include <nlohmann/json.hpp>

#include "suite/enterprise/invalid_curve/invalid_curve_filler.h"
#include "default.h"
#include "config/RunSuiteStatus.h"
#include "logger/report.h"
#include "overview/html_guard.h"
#include "overview/html_utils.h"
#include "suite/result_helper.h"
#include "suite/suite_helper.h"

namespace wpa3_tester::suite::invalid_curve_filler{
using namespace std;
using namespace filesystem;
using namespace nlohmann;

InvalidCurveTestEntry InvalidCurveTestEntry::parse(const path &test_folder){
	auto e = helper::load_result_default<InvalidCurveTestEntry>(test_folder);
	e.test_name = test_folder.filename().string();

	const auto rs = helper::load_test_rs(test_folder);
	e.ap_openssl_version = hostapd::get_openssl_version(*rs, "ap");
	e.ap_hostapd_version = hostapd::get_version(*rs, "ap");
	e.ap_driver = rs->get_actor("ap").get(SK::driver_name);
	e.attacker_driver = rs->get_actor("attacker").get(SK::driver_name);
	return e;
}

vector<InvalidCurveTestEntry> InvalidCurveTestEntry::collect_results(const path &test_data_dir) {
	auto entries = helper::get_results_default<InvalidCurveTestEntry>(test_data_dir);

	ranges::sort(entries, [](const InvalidCurveTestEntry& a, const InvalidCurveTestEntry& b) {
		if (a.connected != b.connected) {return a.connected < b.connected; }
		if (a.ap_openssl_version != b.ap_openssl_version) {return a.ap_openssl_version < b.ap_openssl_version; }
		if (a.ap_driver != b.ap_driver){ return a.ap_driver < b.ap_driver;}
		if (a.attacker_driver != b.attacker_driver) { return a.attacker_driver < b.attacker_driver;}
		if (a.ap_hostapd_version != b.ap_hostapd_version){ return a.ap_hostapd_version < b.ap_hostapd_version;}
		return false;
	});

	return entries;
}

void InvalidCurveTestEntry::render_table(overview::HtmlGuard &f, const string &title,
										const path &suite_data_dir, const path &){

	helper::div_card<InvalidCurveTestEntry>(f, title, suite_data_dir, [&](overview::HtmlGuard& hg,
		const std::vector<InvalidCurveTestEntry>& entries) {

		HtmlPathTable t(hg, entries);

		t.build([&](auto col) {
			col("Test",                 &InvalidCurveTestEntry::test_name);
			col("AP Driver",            &InvalidCurveTestEntry::ap_driver);
			col("Hostapd version",      &InvalidCurveTestEntry::ap_hostapd_version);
			col("Attacker Driver",      &InvalidCurveTestEntry::attacker_driver);
			col("AP openssl version",   &InvalidCurveTestEntry::ap_openssl_version);
			col("Connected?",              &InvalidCurveTestEntry::connected);
		});

		t.render();
	});
}

void generate_report(const RunSuiteStatus &rss){
	const auto run_dir = rss.run_folder();
	const auto entries = helper::get_results_default<InvalidCurveTestEntry>(run_dir);

	report::ReportGuard report(run_dir);
	if(!report) return;

	report << "# Invalid Curve Attack Test Suite Report\n\n";
	report << "Tests whether the AP is vulnerable to EAP-PWD invalid curve attack (CVE-2019-9499).\n\n";

	if(entries.empty()){ report << "No test results found.\n"; return; }

	report << "## Test Results\n\n";
	report << "| Test | AP Driver | Attacker Driver | Result |\n";
	report << "|------|-----------|-----------------|--------|\n";

	for(const auto &e: entries){
		const string result_link = "[" + string(e.connected.value() ? "PASSED" : "FAILED") + "](" + e.test_name + "/" +
				RESULT_NAME + ")";
		report << "| " << report::link(e.test_name , path(e.test_name) / REPORT_NAME) << " | "
			<< e.ap_driver << " | "
			<< e.attacker_driver << " | "
			<< result_link << " |\n";
	}

	report << "\n## Summary\n\n";
	const size_t passed_count = ranges::count_if(entries, [](const auto &e){ return e.connected.value(); });
	report << "- Total Tests: " << entries.size() << "\n";
	report << "- Passed: " << passed_count << "\n";
	report << "- Failed: " << (entries.size() - passed_count) << "\n";
	report << "- Success Rate: " << fixed << setprecision(1) << (100.0 * static_cast<double>(passed_count) /
			static_cast<double>(entries.size())) << "%\n";
}
}
