#include <filesystem>
#include <fstream>
#include <iomanip>
#include <nlohmann/json.hpp>

#include "suite/downgrade/wpa3_trans_downgrade_filler.h"
#include "config/RunSuiteStatus.h"
#include "logger/log.h"
#include "suite/suite_helper.h"
#include "system/utils.h"

namespace wpa3_tester::suite::wpa3_trans_downgrade_filler {
using namespace std;
using namespace filesystem;
using namespace nlohmann;

Wpa3TransDowngradeTestEntry parse_test_folder(const path &test_folder) {
	Wpa3TransDowngradeTestEntry e{};
	e.test_name = test_folder.filename().string();

	const auto result = helper::load_result_json(test_folder);
	if (!result) return e;

	const auto drv     = helper::load_test_drivers(test_folder);
	e.rogue_4way_count = result->value("rogue_4way_count", 0);
	e.downgrade_seen   = result->value("downgrade_seen", false);
	e.passed           = result->value("vulnerable", false);
	e.ap_driver        = helper::get_driver(drv, "access_point");
	e.client_driver    = helper::get_driver(drv, "client");
	return e;
}

vector<Wpa3TransDowngradeTestEntry> get_results(const path &run_dir) {
	auto entries = helper::collect_entries_nested(run_dir, [](const path &p, const path &) {
		return parse_test_folder(p);
	});
	ranges::sort(entries, [](const auto &a, const auto &b) { return a.test_name < b.test_name; });
	return entries;
}

void setup_suite(const RunSuiteStatus &rss) {
	const auto config_dir = rss.run_folder() / "test_config" / "all_actors" / "config";
	create_public_dirs(config_dir);
	copy_f(rss.config_path().parent_path() / "config/hostapd-mana.conf",
			config_dir / "hostapd-mana.conf");
}

void generate_report(RunSuiteStatus &rss) {
	const auto run_dir = rss.run_folder();
	const auto entries = get_results(run_dir);

	auto report = helper::open_report(run_dir / "report.md");
	if (!report.is_open()) return;

	report << "# WPA3 Transition Downgrade Test Suite Report\n\n";
	report << "Tests whether a WPA3-Transition client can be downgraded to WPA2-PSK via a rogue AP.\n\n";

	if (entries.empty()) {
		report << "No test results found.\n";
		report.close();
		return;
	}

	report << "## Test Results\n\n";
	report << "| Test | AP Driver | Client Driver | Rogue 4-way | Downgrade Seen | Vulnerable |\n";
	report << "|------|-----------|---------------|:-----------:|:--------------:|:----------:|\n";

	for (const auto &e : entries) {
		const string name_cell = exists(run_dir / e.test_name / "report.md")
								? "[" + e.test_name + "](" + e.test_name + "/report.md)" : e.test_name;
		const string vuln_link = "[" + string(e.passed.value() ? "yes" : "no") + "](" + e.test_name + "/result.json)";
		report << "| " << name_cell
				<< " | " << e.ap_driver
				<< " | " << e.client_driver
				<< " | " << e.rogue_4way_count
				<< " | " << (e.downgrade_seen ? "yes" : "no")
				<< " | " << vuln_link
				<< " |\n";
	}

	report << "\n## Summary\n\n";
	const size_t vuln_count = ranges::count_if(entries, [](const auto &e) { return e.passed.value(); });
	report << "- Total Tests: " << entries.size() << "\n";
	report << "- Vulnerable: " << vuln_count << "\n";
	report << "- Not vulnerable: " << (entries.size() - vuln_count) << "\n";
	report << "- Vulnerability Rate: " << fixed << setprecision(1)
			<< (100.0 * static_cast<double>(vuln_count) / static_cast<double>(entries.size())) << "%\n";

	report.close();
	set_public_perms(run_dir / "report.md");
	log(LogLevel::INFO, "WPA3 trans downgrade report generated: {}", (run_dir / "report.md").string());
}

}