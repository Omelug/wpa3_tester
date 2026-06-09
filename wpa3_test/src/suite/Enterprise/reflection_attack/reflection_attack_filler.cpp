#include <filesystem>
#include <fstream>
#include <iomanip>
#include <nlohmann/json.hpp>

#include "config/RunSuiteStatus.h"
#include "logger/log.h"
#include "suite/suite_helper.h"
#include "system/utils.h"

namespace wpa3_tester::suite::reflection_attack_filler{
using namespace std;
using namespace filesystem;
using namespace nlohmann;

void generate_report(RunSuiteStatus &rss){
	const auto run_dir = rss.run_folder();

	// test_name, ap_driver, attacker_driver, passed
	vector<tuple<string, string, string, bool>> test_results;

	for(const auto &entry: directory_iterator(run_dir)){
		if(!entry.is_directory()) continue;

		const auto &test_folder = entry.path();
		const auto result = helper::load_result_json(test_folder);
		if(!result) continue;

		const bool passed    = result->value("passed", false);
		const string test_name = test_folder.filename().string();

		const auto drv = helper::load_test_drivers(test_folder);
		test_results.emplace_back(test_name,
			helper::get_driver(drv, "access_point"),
			helper::get_driver(drv, "attacker"),
			passed);
	}

	auto report = helper::open_report(run_dir / "report.md");
	if(!report.is_open()) return;

	report << "# Reflection MAC Generator Test Suite Report\n\n";
	if(test_results.empty()){
		report << "No test results found.\n";
		report.close();
		return;
	}

	report << "## Test Results\n\n";
	report << "| Test | AP Driver | Attacker Driver | Result |\n";
	report << "|------|-----------|-----------------|--------|\n";

	for(const auto &[test_name, ap_drv, att_drv, passed]: test_results){
		const string name_cell   = exists(run_dir / test_name / "report.md")
			? "[" + test_name + "](" + test_name + "/report.md)" : test_name;
		const string result_link = "[" + string(passed ? "PASSED" : "FAILED") + "](" + test_name + "/result.json)";
		report << "| " << name_cell << " | " << ap_drv << " | "
			   << att_drv << " | " << result_link << " |\n";
	}

	report << "\n## Summary\n\n";
	size_t passed_count = ranges::count_if(test_results, [](const auto &r){ return get<3>(r); });
	report << "- Total Tests: " << test_results.size() << "\n";
	report << "- Passed: " << passed_count << "\n";
	report << "- Failed: " << (test_results.size() - passed_count) << "\n";
	report << "- Success Rate: " << fixed << setprecision(1)
		   << (100.0 * static_cast<double>(passed_count) / static_cast<double>(test_results.size())) << "%\n";

	report.close();
	set_public_perms(run_dir / "report.md");

	log(LogLevel::INFO, "Reflection attack report generated: {}", (run_dir / "report.md").string());
}

}