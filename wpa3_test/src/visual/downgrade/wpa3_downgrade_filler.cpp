#include <filesystem>
#include <iomanip>
#include <nlohmann/json.hpp>

#include "visual/downgrade/wpa3_downgrade_filler.h"
#include "default.h"
#include "config/RunSuiteStatus.h"
#include "logger/report.h"
#include "overview/html_guard.h"
#include "overview/html_utils.h"
#include "visual/result_helper.h"
#include "visual/suite_helper.h"
#include "system/utils.h"

namespace wpa3_tester::visual::wpa3_downgrade_filler{
using namespace std;
using namespace filesystem;
using namespace nlohmann;

Wpa3TransDowngradeTestEntry Wpa3TransDowngradeTestEntry::parse(const path &test_folder){
	auto e = helper::load_result_default<Wpa3TransDowngradeTestEntry>(test_folder);
	e.test_name = test_folder.filename().string();

	const auto cfg_path = test_folder / TEST_CONFIG_NAME;
	const auto rs = helper::load_test_rs(test_folder);

	const auto ap = rs->get_actor("ap");
	e.ap_mac = ap->get(SK::mac);
	e.ap_driver = ap->get(SK::driver_name);

	const auto client = rs->get_actor("client");
	e.client_mac = client->get(SK::mac);
	e.client_driver = client->get(SK::driver_name);

	//TODO rogue_ap/attacker  mac
	//TODO WPA3 disable
	return e;
}

void Wpa3TransDowngradeTestEntry::render_table(overview::HtmlGuard &f, const string &title,
	const path &suite_data_dir, const path &){

	helper::div_card<Wpa3TransDowngradeTestEntry>(f, title, suite_data_dir, [&](overview::HtmlGuard& hg,
		const std::vector<Wpa3TransDowngradeTestEntry>& entries) {

		HtmlPathTable t(hg, entries);
		#define COL(name, body) col(name, [&]( [[maybe_unused]] const auto& e) { hg << body; })

		t.build([&](auto col) {
			//COL("Test",               overview::test_name_cell(p, e.test_name, page_dir));
			COL("AP ",				e.ap_mac << "(" << e.ap_driver << ")");
			COL("Client",			e.client_mac << "(" << e.client_driver << ")");
			col("Disconnected",         &Wpa3TransDowngradeTestEntry::disconnected);
			col("Downgrade Seen",       &Wpa3TransDowngradeTestEntry::downgrade_seen);
		})->render();
		#undef COL
	});
}

void setup_suite(const RunSuiteStatus &rss){
	const auto config_dir = rss.run_folder() / TEST_SUITE_CONFIG_DIR / "all_actors" / "config";
	create_public_dirs(config_dir);
	copy_f(rss.config_path().parent_path() / "config/hostapd-mana.conf", config_dir / "hostapd-mana.conf");
}

void generate_report(RunSuiteStatus &rss){
	const auto run_dir = rss.run_folder();
	const auto entries = helper::get_results_default<Wpa3TransDowngradeTestEntry>(run_dir);

	report::ReportGuard report(run_dir);
	if(!report) return;

	report << "# WPA3 Transition Downgrade Test Suite Report\n\n";
	report << "Tests whether a WPA3-Transition client can be downgraded to WPA2-PSK via a rogue AP.\n\n";

	if(entries.empty()){ report << "No test results found.\n"; return; }

	report << "## Test Results\n\n";
	report << "| Test | AP Driver | Client Driver | Downgrade Seen |\n";
	report << "|------|-----------|---------------|:--------------:|\n";

	for(const auto &e: entries){
		report << "| " <<  report::link(e.test_name , path(e.test_name) / REPORT_NAME) << " | "
			<< e.ap_driver << " | "
			<< e.client_driver
			<< " | " << e.downgrade_seen << " |\n";
	}

	report << "\n## Summary\n\n";
	const size_t vuln_count = ranges::count_if(entries, [](const auto &e){ return e.downgrade_seen; });
	report << "- Total Tests: " << entries.size() << "\n";
	report << "- Vulnerable: " << vuln_count << "\n";
	report << "- Not vulnerable: " << (entries.size() - vuln_count) << "\n";
	report << "- Vulnerability Rate: " << fixed << setprecision(1) << (100.0 * static_cast<double>(vuln_count) /
			static_cast<double>(entries.size())) << "%\n";
}
}
