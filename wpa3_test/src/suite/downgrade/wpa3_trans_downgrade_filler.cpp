#include <filesystem>
#include <fstream>
#include <iomanip>
#include <nlohmann/json.hpp>

#include "suite/downgrade/wpa3_trans_downgrade_filler.h"
#include "config/RunSuiteStatus.h"
#include "logger/log.h"
#include "suite/suite_helper.h"
#include "system/utils.h"

namespace wpa3_tester::suite::wpa3_trans_downgrade_filler{
using namespace std;
using namespace filesystem;
using namespace nlohmann;

void setup_suite(const RunSuiteStatus &rss){
	const auto config_dir = rss.run_folder() / "test_config" / "all_actors" / "config";
	create_public_dirs(config_dir);
	copy_f(rss.config_path().parent_path() / "config/hostapd-mana.conf",
		   config_dir / "hostapd-mana.conf");
}

struct TestEntry {
	string test_name;
	string ap_driver;
	string client_driver;
	int    rogue_4way_count;
	bool   downgrade_seen;
	bool   vulnerable;
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
		e.test_name       = test_folder.filename().string();
		e.rogue_4way_count= result->value("rogue_4way_count", 0);
		e.downgrade_seen  = result->value("downgrade_seen", false);
		e.vulnerable      = result->value("vulnerable", false);
		e.ap_driver       = helper::get_driver(drv, "access_point");
		e.client_driver   = helper::get_driver(drv, "client");
		entries.push_back(std::move(e));
	}

	ranges::sort(entries, [](const auto &a, const auto &b){ return a.test_name < b.test_name; });

	auto report = helper::open_report(run_dir / "report.md");
	if(!report.is_open()) return;

	report << "# WPA3 Transition Downgrade Test Suite Report\n\n";
	report << "Tests whether a WPA3-Transition client can be downgraded to WPA2-PSK via a rogue AP.\n\n";

	if(entries.empty()){
		report << "No test results found.\n";
		report.close();
		return;
	}

	report << "## Test Results\n\n";
	report << "| Test | AP Driver | Client Driver | Rogue 4-way | Downgrade Seen | Vulnerable |\n";
	report << "|------|-----------|---------------|:-----------:|:--------------:|:----------:|\n";

	for(const auto &e: entries){
		const string name_cell = exists(run_dir / e.test_name / "report.md")
			? "[" + e.test_name + "](" + e.test_name + "/report.md)" : e.test_name;
		const string vuln_link = "[" + string(e.vulnerable ? "yes" : "no") + "](" + e.test_name + "/result.json)";
		report << "| " << name_cell
			   << " | " << e.ap_driver
			   << " | " << e.client_driver
			   << " | " << e.rogue_4way_count
			   << " | " << (e.downgrade_seen ? "yes" : "no")
			   << " | " << vuln_link
			   << " |\n";
	}

	report << "\n## Summary\n\n";
	const size_t vuln_count = ranges::count_if(entries, [](const auto &e){ return e.vulnerable; });
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