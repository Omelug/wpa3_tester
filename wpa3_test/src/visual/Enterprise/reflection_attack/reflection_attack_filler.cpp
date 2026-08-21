#include <filesystem>
#include <iomanip>
#include <nlohmann/json.hpp>

#include "visual/enterprise/reflection_attack/reflection_attack_filler.h"

#include "default.h"
#include "config/RunSuiteStatus.h"
#include "logger/report.h"
#include "overview/html_guard.h"
#include "overview/html_utils.h"
#include "visual/result_helper.h"
#include "visual/suite_helper.h"

namespace wpa3_tester::visual::reflection_attack_filler{
using namespace std;
using namespace filesystem;
using namespace nlohmann;

ReflectionAttackTestEntry ReflectionAttackTestEntry::parse(const path &test_folder){
	auto e = helper::load_result_default<ReflectionAttackTestEntry>(test_folder);
	e.test_name = test_folder.filename().string();

	const auto rs = helper::load_test_rs(test_folder);
	e.ap_hostapd_version = hostapd::get_version(*rs, "ap");
	e.ap_driver = rs->get_actor("ap").get(SK::driver_name);
	e.attacker_driver = rs->get_actor("attacker").get(SK::driver_name);
	return e;
}

vector<ReflectionAttackTestEntry> ReflectionAttackTestEntry::collect_results(const path &test_data_dir) {
	auto entries = helper::get_results_default<ReflectionAttackTestEntry>(test_data_dir);

	ranges::sort(entries, [](const ReflectionAttackTestEntry& a, const ReflectionAttackTestEntry& b) {
		return tie(a.connected, a.ap_driver, a.attacker_driver, a.ap_hostapd_version) <
		   tie(b.connected, b.ap_driver, b.attacker_driver, b.ap_hostapd_version);
	});

	return entries;
}

void ReflectionAttackTestEntry::render_table(overview::HtmlGuard &f, const string &title,
	const path &suite_data_dir, const path &){

	helper::div_card<ReflectionAttackTestEntry>(f, title, suite_data_dir, [&](overview::HtmlGuard& hg,
		const std::vector<ReflectionAttackTestEntry>& entries) {

		HtmlPathTable t(hg, entries);

		t.build([&](auto col) {
			col("Test",                 &ReflectionAttackTestEntry::test_name);
			col("AP Driver",            &ReflectionAttackTestEntry::ap_driver);
			col("Hostapd version",      &ReflectionAttackTestEntry::ap_hostapd_version);
			col("Attacker Driver",      &ReflectionAttackTestEntry::attacker_driver);
			col("Connected?",           &ReflectionAttackTestEntry::connected);
		})->render({"Test"});
	});
}

void generate_report(RunSuiteStatus &rss){
	const auto run_dir = rss.run_folder();
	const auto entries = helper::get_results_default<ReflectionAttackTestEntry>(run_dir);

	report::ReportGuard report(run_dir);
	if(!report) return;

	report << "# Reflection MAC Generator Test Suite Report\n\n";

	if(entries.empty()){ report << "No test results found.\n"; return; }

	report << "## Test Results\n\n";
	report << "| Test | AP Driver | Attacker Driver | Result |\n";
	report << "|------|-----------|-----------------|--------|\n";

	for(const auto &e: entries){
		const string result_link = "[" + string(e.connected.value() ? "PASSED" : "FAILED") + "](" + e.test_name + "/" +
				RESULT_NAME + ")";
		report << "| " <<  report::link(e.test_name , path(e.test_name) / REPORT_NAME) << " | "
			<< e.ap_driver << " | "
			<< e.attacker_driver << " | "
			<< result_link << " |\n";
	}
}
}
