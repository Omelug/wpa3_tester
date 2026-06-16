#include <filesystem>
#include <fstream>
#include <iomanip>
#include <nlohmann/json.hpp>

#include "suite/two_iface/active_test_filler.h"
#include "config/RunSuiteStatus.h"
#include "logger/log.h"
#include "suite/suite_helper.h"
#include "system/utils.h"

namespace wpa3_tester::suite::active_test_filler {
using namespace std;
using namespace filesystem;
using namespace nlohmann;

ActiveTestEntry parse_test_folder(const path &test_folder) {
	ActiveTestEntry e{};
	e.test_name = test_folder.filename().string();

	const auto result = helper::load_result_json(test_folder);
	if (!result) return e;

	const auto rs  = helper::load_test_rs(test_folder);
	e.acked        = result->value("acked", 0);
	e.not_acked    = result->value("not_acked", 0);
	e.passed       = result->value("success", false);
	e.tx_driver    = rs->get_actor("transceiver").get(SK::driver_name);
	e.rx_driver    = rs->get_actor("receiver").get(SK::driver_name);
	return e;
}

vector<ActiveTestEntry> get_results(const path &run_dir) {
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

	report << "# Active Test Suite Report\n\n";
	report << "Tests whether a monitor-mode interface can both inject and receive ACKs (two-interface active TX test).\n\n";

	if (entries.empty()) {
		report << "No test results found.\n";
		report.close();
		return;
	}

	report << "## Test Results\n\n";
	report << "| Test | TX Driver | RX Driver | Acked | Not Acked | Result |\n";
	report << "|------|-----------|-----------|:-----:|:---------:|:------:|\n";

	for (const auto &e : entries) {
		const string name_cell   = exists(run_dir / e.test_name / "report.md")
			? "[" + e.test_name + "](" + e.test_name + "/report.md)" : e.test_name;
		const string result_link = "[" + string(e.passed.value() ? "PASSED" : "FAILED") + "](" + e.test_name + "/result.json)";
		report << "| " << name_cell
		       << " | " << e.tx_driver
		       << " | " << e.rx_driver
		       << " | " << e.acked
		       << " | " << e.not_acked
		       << " | " << result_link
		       << " |\n";
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
	log(LogLevel::INFO, "Active test report generated: {}", (run_dir / "report.md").string());
}

}
