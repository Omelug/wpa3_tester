#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>

#include "suite/downgrade/owe_trans_filler.h"
#include "default.h"
#include "config/RunSuiteStatus.h"
#include "suite/result_helper.h"
#include "suite/suite_helper.h"

namespace wpa3_tester::suite::owe_trans_filler{
using namespace std;
using namespace filesystem;
using namespace nlohmann;

OweTransTestEntry OweTransTestEntry::parse(const path &test_folder){
	auto e = helper::load_result_default<OweTransTestEntry>(test_folder);
	e.test_name = test_folder.filename().string();

	const auto rs = helper::load_test_rs(test_folder);
	e.ap_driver = rs->get_actor("access_point").get(SK::driver_name);
	e.client_driver = rs->get_actor("client").get(SK::driver_name);
	e.attacker_driver = rs->get_actor("attacker").get(SK::driver_name);
	return e;
}

void generate_report(RunSuiteStatus &rss){
	const auto run_dir = rss.run_folder();
	const auto entries = helper::get_results_default<OweTransTestEntry>(run_dir);

	helper::ReportGuard report(run_dir);
	if(!report) return;

	report << "# OWE Transition Probe Leak Test Suite Report\n\n";
	report << "Tests whether a client leaks probe requests after disconnection from an OWE AP.\n\n";

	if(entries.empty()){ report << "No test results found.\n"; return; }

	report << "## Test Results\n\n";
	report << "| Test | AP Driver | Client Driver | Attacker Driver | Probes | Disconnected | Probe found |\n";
	report << "|------|-----------|---------------|-----------------|:------:|:------------:|:----------:|\n";

	for(const auto &e: entries){
		const string name_cell = exists(run_dir / e.test_name / REPORT_NAME)
								? "[" + e.test_name + "](" + e.test_name + "/" + REPORT_NAME + ")"
								: e.test_name;
		const string vuln_link = "[" + string(e.probe_count > 0 ? "yes" : "no") + "](" + e.test_name + "/" +
				RESULT_NAME + ")";
		report << "| " << name_cell << " | " << e.ap_driver << " | " << e.client_driver << " | " << e.attacker_driver
				<< " | " << e.probe_count << " | " << (e.disconnected ? "yes" : "no") << " | " << vuln_link << " |\n";
	}
}
}