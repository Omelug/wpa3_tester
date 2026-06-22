#include <filesystem>
#include <iomanip>
#include <nlohmann/json.hpp>

#include "suite/Enterprise/reflection_attack/reflection_attack_filler.h"

#include "default.h"
#include "config/RunSuiteStatus.h"
#include "logger/report.h"
#include "suite/result_helper.h"
#include "suite/suite_helper.h"

namespace wpa3_tester::suite::reflection_attack_filler{
using namespace std;
using namespace filesystem;
using namespace nlohmann;

ReflectionAttackTestEntry ReflectionAttackTestEntry::parse(const path &test_folder){
	auto e = helper::load_result_default<ReflectionAttackTestEntry>(test_folder);
	e.test_name = test_folder.filename().string();

	const auto rs = helper::load_test_rs(test_folder);
	e.ap_driver = rs->get_actor("access_point").get(SK::driver_name);
	e.attacker_driver = rs->get_actor("attacker").get(SK::driver_name);
	return e;
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
		const string result_link = "[" + string(e.passed.value() ? "PASSED" : "FAILED") + "](" + e.test_name + "/" +
				RESULT_NAME + ")";
		report << "| " <<  report::link(e.test_name , path(e.test_name) / REPORT_NAME) << " | "
			<< e.ap_driver << " | "
			<< e.attacker_driver << " | "
			<< result_link << " |\n";
	}

	report << "\n## Summary\n\n";
	const size_t passed_count = ranges::count_if(entries, [](const auto &e){ return e.passed.value(); });
	report << "- Total Tests: " << entries.size() << "\n";
	report << "- Passed: " << passed_count << "\n";
	report << "- Failed: " << (entries.size() - passed_count) << "\n";
	report << "- Success Rate: " << fixed << setprecision(1) << (100.0 * static_cast<double>(passed_count) /
			static_cast<double>(entries.size())) << "%\n";
}
}
