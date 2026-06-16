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

namespace wpa3_tester::suite::invalid_curve_filler {
using namespace std;
using namespace filesystem;
using namespace nlohmann;

void setup_suite(const RunSuiteStatus &rss) {
	enterprise_filler_helper::setup_suite(rss);
}

InvalidCurveTestEntry parse_test_folder(const path &test_folder) {
	InvalidCurveTestEntry e{};
	e.test_name = test_folder.filename().string();

	const auto result = helper::load_result_json(test_folder);
	if (!result) return e;

	const auto drv    = helper::load_test_drivers(test_folder);
	e.passed          = result->value("passed", false);
	e.ap_driver       = helper::get_driver(drv, "access_point");
	e.attacker_driver = helper::get_driver(drv, "attacker");
	return e;
}

vector<InvalidCurveTestEntry> get_results(const path &run_dir) {
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

	report << "# Invalid Curve Attack Test Suite Report\n\n";
	report << "Tests whether the AP is vulnerable to EAP-PWD invalid curve attack (CVE-2019-9499).\n\n";

	if (entries.empty()) {
		report << "No test results found.\n";
		report.close();
		return;
	}

	report << "## Test Results\n\n";
	report << "| Test | AP Driver | Attacker Driver | Result |\n";
	report << "|------|-----------|-----------------|--------|\n";

	for (const auto &e : entries) {
		const string name_cell   = exists(run_dir / e.test_name / "report.md")
			? "[" + e.test_name + "](" + e.test_name + "/report.md)" : e.test_name;
		const string result_link = "[" + string(e.passed.value() ? "PASSED" : "FAILED") + "](" + e.test_name + "/result.json)";
		report << "| " << name_cell << " | " << e.ap_driver << " | "
		       << e.attacker_driver << " | " << result_link << " |\n";
	}

	report << "\n## Summary\n\n";
	const size_t passed_count = ranges::count_if(entries, [](const auto &e) { return e.passed.value(); });
	report << "- Total Tests: " << entries.size() << "\n";
	report << "- Passed: " << passed_count << "\n";
	report << "- Failed: " << (entries.size() - passed_count) << "\n";
	report << "- Success Rate: " << fixed << setprecision(1)
	       << (100.0 * static_cast<double>(passed_count) / static_cast<double>(entries.size())) << "%\n";

	report.close();
	set_public_perms(run_dir / "report.md");
	log(LogLevel::INFO, "Invalid curve report generated: {}", (run_dir / "report.md").string());
}

}
