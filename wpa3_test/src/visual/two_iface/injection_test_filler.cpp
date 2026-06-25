#include <filesystem>
#include <nlohmann/json.hpp>

#include "suite/two_iface/injection_test_filler.h"

#include "default.h"
#include "config/RunSuiteStatus.h"
#include "logger/report.h"
#include "suite/result_helper.h"
#include "suite/suite_helper.h"

namespace wpa3_tester::suite::injection_test_filler{
using namespace std;
using namespace filesystem;
using namespace nlohmann;

InjectionTestEntry InjectionTestEntry::parse(const path &test_folder){
	InjectionTestEntry e{};
	e.test_name = test_folder.filename().string();
	e.tests_passed = 0;
	e.tests_total = 0;

	const auto result = helper::load_result_json(test_folder);
	if(!result) return e;

	const auto rs = helper::load_test_rs(test_folder);
	e.tx_driver = rs->get_actor("transceiver").get(SK::driver_name);
	e.rx_driver = rs->get_actor("receiver").get(SK::driver_name);

	if(result->contains("tests") && result->at("tests").is_object()){
		for(const auto &[name, val]: result->at("tests").items()){
			++e.tests_total;
			if(val.value("result", "") == "PASSED"){
				++e.tests_passed;
			} else{
				e.failures.emplace_back(name, val.value("detail", ""));
			}
		}
	}

	e.passed = (e.tests_passed == e.tests_total && e.tests_total > 0);
	return e;
}

void generate_report(RunSuiteStatus &rss){
	const auto run_dir = rss.run_folder();
	const auto entries = helper::get_results_default<InjectionTestEntry>(run_dir);

	report::ReportGuard r(run_dir);
	if(!r) return;

	r << "# Injection Test Suite Report\n\n";
	r << "Tests frame injection capability across different driver combinations.\n\n";

	if(entries.empty()){ r << "No test results found.\n"; return; }

	r << "## Test Results\n\n";
	r << "| Test | TX Driver | RX Driver | Passed | Total | All Passed |\n";
	r << "|------|-----------|-----------|:------:|:-----:|:----------:|\n";

	for(const auto &e: entries){
		const string name_cell = exists(run_dir / e.test_name / REPORT_NAME)
								? "[" + e.test_name + "](" + e.test_name + "/" + REPORT_NAME + ")"
								: e.test_name;
		const string pass_link = "[" + string(e.passed.value() ? "yes" : "no") + "](" + e.test_name + "/" +
				RESULT_NAME + ")";
		r << "| "
			<< name_cell << " | "
			<< e.tx_driver << " | "
			<< e.rx_driver << " | "
			<< e.tests_passed << " | "
			<< e.tests_total << " | "
			<< pass_link << " |\n";
	}

	bool any_failures = false;
	for(const auto &e: entries){
		if(e.failures.empty()) continue;
		if(!any_failures){ r << "\n## Failures\n\n"; any_failures = true; }
		r << "### " << e.test_name << "\n\n";
		r << "| Sub-test | Detail |\n|----------|--------|\n";
		for(const auto &[name, detail]: e.failures)
			r << "| " << name << " | " << (detail.empty() ? "-" : detail) << " |\n";
		r << "\n";
	}

	r << "\n## Summary\n\n";
	const size_t all_passed_count = ranges::count_if(entries, [](const auto &e){ return e.passed.value(); });
	r << "- Total Tests: " << entries.size() << "\n";
	r << "- All sub-tests passed: " << all_passed_count << "\n";
	r << "- Partial/full failures: " << (entries.size() - all_passed_count) << "\n";
}
}
