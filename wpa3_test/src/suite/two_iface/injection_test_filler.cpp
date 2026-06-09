#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>

#include "suite/two_iface/injection_test_filler.h"
#include "config/RunSuiteStatus.h"
#include "logger/log.h"
#include "suite/suite_helper.h"
#include "system/utils.h"

namespace wpa3_tester::suite::injection_test_filler{
using namespace std;
using namespace filesystem;
using namespace nlohmann;

struct TestEntry {
	string test_name;
	string tx_driver;
	string rx_driver;
	int    tests_passed;
	int    tests_total;
	// failed test names with detail
	vector<pair<string,string>> failures;
};

void generate_report(RunSuiteStatus &rss){
	const auto run_dir = rss.run_folder();

	vector<TestEntry> entries;

	for(const auto &entry: directory_iterator(run_dir)){
		if(!entry.is_directory()) continue;

		const auto &test_folder = entry.path();
		const auto result = helper::load_result_json(test_folder);
		if(!result) continue;

		const auto drv = helper::load_test_drivers(test_folder);

		TestEntry e;
		e.test_name = test_folder.filename().string();
		e.tx_driver = helper::get_driver(drv, "transceiver");
		e.rx_driver = helper::get_driver(drv, "receiver");
		e.tests_passed = 0;
		e.tests_total  = 0;

		if(result->contains("tests") && result->at("tests").is_object()){
			for(const auto &[name, val] : result->at("tests").items()){
				++e.tests_total;
				if(val.value("result", "") == "PASSED"){
					++e.tests_passed;
				} else {
					e.failures.emplace_back(name, val.value("detail", ""));
				}
			}
		}

		entries.push_back(std::move(e));
	}

	ranges::sort(entries, [](const auto &a, const auto &b){ return a.test_name < b.test_name; });

	auto report = helper::open_report(run_dir / "report.md");
	if(!report.is_open()) return;

	report << "# Injection Test Suite Report\n\n";
	report << "Tests frame injection capability across different driver combinations.\n\n";

	if(entries.empty()){
		report << "No test results found.\n";
		report.close();
		return;
	}

	report << "## Test Results\n\n";
	report << "| Test | TX Driver | RX Driver | Passed | Total | All Passed |\n";
	report << "|------|-----------|-----------|:------:|:-----:|:----------:|\n";

	for(const auto &e: entries){
		const bool all_passed = (e.tests_passed == e.tests_total && e.tests_total > 0);
		report << "| " << e.test_name
			   << " | " << e.tx_driver
			   << " | " << e.rx_driver
			   << " | " << e.tests_passed
			   << " | " << e.tests_total
			   << " | " << (all_passed ? "yes" : "no")
			   << " |\n";
	}

	// per-entry failure details
	bool any_failures = false;
	for(const auto &e: entries){
		if(e.failures.empty()) continue;
		if(!any_failures){
			report << "\n## Failures\n\n";
			any_failures = true;
		}
		report << "### " << e.test_name << "\n\n";
		report << "| Sub-test | Detail |\n|----------|--------|\n";
		for(const auto &[name, detail]: e.failures)
			report << "| " << name << " | " << (detail.empty() ? "-" : detail) << " |\n";
		report << "\n";
	}

	report << "\n## Summary\n\n";
	const size_t all_passed_count = ranges::count_if(entries, [](const auto &e){
		return e.tests_passed == e.tests_total && e.tests_total > 0;
	});
	report << "- Total Tests: " << entries.size() << "\n";
	report << "- All sub-tests passed: " << all_passed_count << "\n";
	report << "- Partial/full failures: " << (entries.size() - all_passed_count) << "\n";

	report.close();
	set_public_perms(run_dir / "report.md");
	log(LogLevel::INFO, "Injection test report generated: {}", (run_dir / "report.md").string());
}

}
