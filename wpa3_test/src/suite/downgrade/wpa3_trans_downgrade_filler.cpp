#include <filesystem>
#include <fstream>
#include <iomanip>
#include <nlohmann/json.hpp>

#include "default.h"
#include "suite/downgrade/wpa3_trans_downgrade_filler.h"
#include "config/RunSuiteStatus.h"
#include "logger/log.h"
#include "suite/result_helper.h"
#include "suite/suite_helper.h"
#include "system/utils.h"

namespace wpa3_tester::suite::wpa3_trans_downgrade_filler{
using namespace std;
using namespace filesystem;
using namespace nlohmann;

Wpa3TransDowngradeTestEntry Wpa3TransDowngradeTestEntry::parse(const path &test_folder){
	auto e = helper::load_result_default<Wpa3TransDowngradeTestEntry>(test_folder);
	e.test_name = test_folder.filename().string();

	const auto rs = helper::load_test_rs(test_folder);
	e.ap_driver = rs->get_actor("access_point").get(SK::driver_name);
	e.client_driver = rs->get_actor("client").get(SK::driver_name);
	return e;
}

void setup_suite(const RunSuiteStatus &rss){
	const auto config_dir = rss.run_folder() / TEST_SUITE_CONFIG_DIR / "all_actors" / "config";
	create_public_dirs(config_dir);
	copy_f(rss.config_path().parent_path() / "config/hostapd-mana.conf", config_dir / "hostapd-mana.conf");
}

void generate_report(RunSuiteStatus &rss){
	const auto run_dir = rss.run_folder();
	const auto entries = helper::get_results_default<Wpa3TransDowngradeTestEntry>(run_dir);

	auto report = helper::open_report(run_dir);
	if(!report.is_open()) return;

	report << "# WPA3 Transition Downgrade Test Suite Report\n\n";
	report << "Tests whether a WPA3-Transition client can be downgraded to WPA2-PSK via a rogue AP.\n\n";

	if(entries.empty()){
		report << "No test results found.\n";
		report.close();
		return;
	}

	report << "## Test Results\n\n";
	report << "| Test | AP Driver | Client Driver | Downgrade Seen |\n";
	report << "|------|-----------|---------------|:--------------:|\n";

	for(const auto &e: entries){
		const string name_cell = exists(run_dir / e.test_name / REPORT_NAME)
								? "[" + e.test_name + "](" + e.test_name + "/" + REPORT_NAME + ")"
								: e.test_name;
		report << "| " << name_cell << " | " << e.ap_driver << " | " << e.client_driver
				//<< " | " << e.rogue_4way_count
				<< " | " << (e.downgrade_seen ? "yes" : "no") << " |\n";
	}

	report << "\n## Summary\n\n";
	const size_t vuln_count = ranges::count_if(entries, [](const auto &e){ return e.downgrade_seen; });
	report << "- Total Tests: " << entries.size() << "\n";
	report << "- Vulnerable: " << vuln_count << "\n";
	report << "- Not vulnerable: " << (entries.size() - vuln_count) << "\n";
	report << "- Vulnerability Rate: " << fixed << setprecision(1) << (100.0 * static_cast<double>(vuln_count) /
		static_cast<double>(entries.size())) << "%\n";

	report.close();
	set_public_perms(run_dir / REPORT_NAME);
	log(LogLevel::INFO, "WPA3 trans downgrade report generated: {}", run_dir / REPORT_NAME);
}
}
