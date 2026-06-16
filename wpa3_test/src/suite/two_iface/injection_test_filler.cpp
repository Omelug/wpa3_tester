#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>

#include "suite/two_iface/injection_test_filler.h"
#include "config/RunSuiteStatus.h"
#include "logger/log.h"
#include "suite/suite_helper.h"
#include "system/utils.h"

namespace wpa3_tester::suite::injection_test_filler {
using namespace std;
using namespace filesystem;
using namespace nlohmann;

InjectionTestEntry parse_test_folder(const path &test_folder) {
	InjectionTestEntry e{};
	e.test_name    = test_folder.filename().string();
	e.tests_passed = 0;
	e.tests_total  = 0;

	const auto result = helper::load_result_json(test_folder);
	if (!result) return e;

	const auto rs  = helper::load_test_rs(test_folder);
	e.tx_driver    = rs->get_actor("transceiver").get(SK::driver_name);
	e.rx_driver    = rs->get_actor("receiver").get(SK::driver_name);

	if (result->contains("tests") && result->at("tests").is_object()) {
		for (const auto &[name, val] : result->at("tests").items()) {
			++e.tests_total;
			if (val.value("result", "") == "PASSED") {
				++e.tests_passed;
			} else {
				e.failures.emplace_back(name, val.value("detail", ""));
			}
		}
	}

	e.passed = (e.tests_passed == e.tests_total && e.tests_total > 0);
	return e;
}

vector<InjectionTestEntry> get_results(const path &run_dir) {
	auto entries = helper::collect_entries_nested(run_dir, [](const path &p, const path &) {
		return parse_test_folder(p);
	});
	ranges::sort(entries, [](const auto &a, const auto &b) { return a.test_name < b.test_name; });
	return entries;
}

void generate_report(RunSuiteStatus &rss) {
	const auto run_dir = rss.run_folder();
	const auto entries = get_results(run_dir);

	auto report = helper::open_report(run_dir / "report.md");
	if (!report.is_open()) return;

	report << "# Injection Test Suite Report\n\n";
	report << "Tests frame injection capability across different driver combinations.\n\n";

	if (entries.empty()) {
		report << "No test results found.\n";
		report.close();
		return;
	}

	report << "## Test Results\n\n";
	report << "| Test | TX Driver | RX Driver | Passed | Total | All Passed |\n";
	report << "|------|-----------|-----------|:------:|:-----:|:----------:|\n";

	for (const auto &e : entries) {
		const string name_cell = exists(run_dir / e.test_name / "report.md")
			? "[" + e.test_name + "](" + e.test_name + "/report.md)" : e.test_name;
		const string pass_link = "[" + string(e.passed.value() ? "yes" : "no") + "](" + e.test_name + "/result.json)";
		report << "| " << name_cell
		       << " | " << e.tx_driver
		       << " | " << e.rx_driver
		       << " | " << e.tests_passed
		       << " | " << e.tests_total
		       << " | " << pass_link
		       << " |\n";
	}

	bool any_failures = false;
	for (const auto &e : entries) {
		if (e.failures.empty()) continue;
		if (!any_failures) {
			report << "\n## Failures\n\n";
			any_failures = true;
		}
		report << "### " << e.test_name << "\n\n";
		report << "| Sub-test | Detail |\n|----------|--------|\n";
		for (const auto &[name, detail] : e.failures)
			report << "| " << name << " | " << (detail.empty() ? "-" : detail) << " |\n";
		report << "\n";
	}

	report << "\n## Summary\n\n";
	const size_t all_passed_count = ranges::count_if(entries, [](const auto &e) { return e.passed.value(); });
	report << "- Total Tests: " << entries.size() << "\n";
	report << "- All sub-tests passed: " << all_passed_count << "\n";
	report << "- Partial/full failures: " << (entries.size() - all_passed_count) << "\n";

	report.close();
	set_public_perms(run_dir / "report.md");
	log(LogLevel::INFO, "Injection test report generated: {}", (run_dir / "report.md").string());
}

}
