#include <filesystem>
#include <fstream>
#include <iomanip>
#include <nlohmann/json.hpp>

#include "suite/Enterprise/reflection_attack/reflection_attack_filler.h"
#include "config/RunSuiteStatus.h"
#include "logger/log.h"
#include "suite/suite_helper.h"
#include "system/utils.h"

namespace wpa3_tester::suite::reflection_attack_filler {
using namespace std;
using namespace filesystem;
using namespace nlohmann;

ReflectionAttackTestEntry parse_test_folder(const path &test_folder) {
	ReflectionAttackTestEntry e{};
	e.test_name = test_folder.filename().string();

	const auto result = helper::load_result_json(test_folder);
	if (!result) return e;

	const auto drv    = helper::load_test_drivers(test_folder);
	e.passed          = result->value("passed", false);
	e.ap_driver       = helper::get_driver(drv, "access_point");
	e.attacker_driver = helper::get_driver(drv, "attacker");
	return e;
}

vector<ReflectionAttackTestEntry> get_results(const path &run_dir) {
	vector<ReflectionAttackTestEntry> entries;
	for (const auto &entry : directory_iterator(run_dir)) {
		if (!entry.is_directory()) continue;
		auto e = parse_test_folder(entry.path());
		if (!e.passed.has_value()) continue;
		entries.push_back(std::move(e));
	}
	ranges::sort(entries, [](const auto &a, const auto &b) { return a.test_name < b.test_name; });
	return entries;
}

void generate_report(RunSuiteStatus &rss) {
	const auto run_dir = rss.run_folder();
	const auto entries = get_results(run_dir);

	auto report = helper::open_report(run_dir / "report.md");
	if (!report.is_open()) return;

	report << "# Reflection MAC Generator Test Suite Report\n\n";

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
	log(LogLevel::INFO, "Reflection attack report generated: {}", (run_dir / "report.md").string());
}

}
