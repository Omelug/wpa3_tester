#include <filesystem>
#include <fstream>
#include <iomanip>
#include <nlohmann/json.hpp>

#include "suite/Enterprise/invalid_curve/invalid_curve_filler.h"
#include "config/RunSuiteStatus.h"
#include "logger/log.h"
#include "suite/suite_helper.h"
#include "suite/Enterprise/enterprise_filler_helper.h"
#include "system/utils.h"

namespace wpa3_tester::suite::invalid_curve_filler{
using namespace std;
using namespace filesystem;
using namespace nlohmann;

void setup_suite(const RunSuiteStatus &rss){
	enterprise_filler_helper::setup_suite(rss);
}

void generate_report(RunSuiteStatus &rss){
	const auto run_dir = rss.run_folder();

	// test_name, ap_driver, attacker_driver, passed
	vector<tuple<string, string, string, bool>> test_results;

	for(const auto &entry: directory_iterator(run_dir)){
		if(!entry.is_directory()) continue;

		const auto &test_folder = entry.path();
		const auto result = helper::load_result_json(test_folder);
		if(!result) continue;

		const bool passed      = result->value("passed", false);
		const string test_name = test_folder.filename().string();
		const auto drv         = helper::load_test_drivers(test_folder);

		test_results.emplace_back(test_name,
			helper::get_driver(drv, "access_point"),
			helper::get_driver(drv, "attacker"),
			passed);
	}

	ranges::sort(test_results, [](const auto &a, const auto &b){
		return get<0>(a) < get<0>(b);
	});

	auto report = helper::open_report(run_dir / "report.md");
	if(!report.is_open()) return;

	report << "# Invalid Curve Attack Test Suite Report\n\n";
	report << "Tests whether the AP is vulnerable to EAP-PWD invalid curve attack (CVE-2019-9499).\n\n";

	if(test_results.empty()){
		report << "No test results found.\n";
		report.close();
		return;
	}

	report << "## Test Results\n\n";
	report << "| Test | AP Driver | Attacker Driver | Result |\n";
	report << "|------|-----------|-----------------|--------|\n";

	for(const auto &[test_name, ap_drv, att_drv, passed]: test_results){
		const string result_link = "[" + string(passed ? "PASSED" : "FAILED") + "](" + test_name + "/result.json)";
		report << "| " << test_name << " | " << ap_drv << " | "
			   << att_drv << " | " << result_link << " |\n";
	}

	report << "\n## Summary\n\n";
	const size_t passed_count = ranges::count_if(test_results, [](const auto &r){ return get<3>(r); });
	report << "- Total Tests: " << test_results.size() << "\n";
	report << "- Passed: " << passed_count << "\n";
	report << "- Failed: " << (test_results.size() - passed_count) << "\n";
	report << "- Success Rate: " << fixed << setprecision(1)
		   << (100.0 * static_cast<double>(passed_count) / static_cast<double>(test_results.size())) << "%\n";

	report.close();
	set_public_perms(run_dir / "report.md");
	log(LogLevel::INFO, "Invalid curve report generated: {}", (run_dir / "report.md").string());
}

}