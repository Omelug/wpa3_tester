#include <filesystem>
#include <fstream>
#include <iomanip>
#include <nlohmann/json.hpp>

#include "default.h"
#include "config/RunSuiteStatus.h"
#include "logger/log.h"
#include "suite/downgrade/owe_trans_filler.h"
#include "suite/suite_helper.h"
#include "system/utils.h"

namespace wpa3_tester::suite::owe_trans_filler {
using namespace std;
using namespace filesystem;
using namespace nlohmann;

OweTransTestEntry OweTransTestEntry::parse(const path &test_folder){
	OweTransTestEntry e{};
	e.test_name = test_folder.filename().string();

	const auto result = helper::load_result_json(test_folder);
	if (!result) return e;

	const auto rs     = helper::load_test_rs(test_folder);
	e.probe_count     = result->value("probe_requests_detected", 0);
	e.disconnected    = result->value("disconnected", false);
	e.passed          = result->value("vulnerable", false);

	e.ap_driver       = rs->get_actor("access_point").get(SK::driver_name);
	e.client_driver   = rs->get_actor("client").get(SK::driver_name);
	e.attacker_driver = rs->get_actor("attacker").get(SK::driver_name);
	return e;
}

void generate_report(RunSuiteStatus &rss) {
	const auto run_dir = rss.run_folder();
	const auto entries = helper::get_results_default<OweTransTestEntry>(run_dir);

	auto report = helper::open_report(run_dir);
	if (!report.is_open()) return;

	report << "# OWE Transition Probe Leak Test Suite Report\n\n";
	report << "Tests whether a client leaks probe requests after disconnection from an OWE AP.\n\n";

	if (entries.empty()) {
		report << "No test results found.\n";
		report.close();
		return;
	}

	report << "## Test Results\n\n";
	report << "| Test | AP Driver | Client Driver | Attacker Driver | Probes | Disconnected | Vulnerable |\n";
	report << "|------|-----------|---------------|-----------------|:------:|:------------:|:----------:|\n";

	for (const auto &e : entries) {
		const string name_cell = exists(run_dir / e.test_name /REPORT_NAME)
			? "[" + e.test_name + "](" + e.test_name + "/" + REPORT_NAME+ ")" : e.test_name;
		const string vuln_link = "[" + string(e.passed.value() ? "yes" : "no") + "](" + e.test_name + "/" + RESULT_NAME+ ")";
		report << "| " << name_cell
		       << " | " << e.ap_driver
		       << " | " << e.client_driver
		       << " | " << e.attacker_driver
		       << " | " << e.probe_count
		       << " | " << (e.disconnected ? "yes" : "no")
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
	set_public_perms(run_dir /REPORT_NAME);
	log(LogLevel::INFO, "OWE trans report generated: {}", run_dir/REPORT_NAME);
}

}