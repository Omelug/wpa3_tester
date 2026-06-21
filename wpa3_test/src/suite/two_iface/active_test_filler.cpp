#include <filesystem>
#include <fstream>
#include <iomanip>
#include <nlohmann/json.hpp>

#include "suite/two_iface/active_test_filler.h"

#include "default.h"
#include "config/RunSuiteStatus.h"
#include "suite/result_helper.h"
#include "suite/suite_helper.h"

namespace wpa3_tester::suite::active_test_filler{
using namespace std;
using namespace filesystem;
using namespace nlohmann;

ActiveTestEntry ActiveTestEntry::parse(const path &test_folder){
	auto e = helper::load_result_default<ActiveTestEntry>(test_folder);
	e.test_name = test_folder.filename().string();

	const auto rs = helper::load_test_rs(test_folder);
	e.tx_driver = rs->get_actor("transceiver").get(SK::driver_name);
	e.rx_driver = rs->get_actor("receiver").get(SK::driver_name);
	return e;
}

void generate_report(RunSuiteStatus &rss){
	const auto run_dir = rss.run_folder();
	const auto entries = helper::get_results_default<ActiveTestEntry>(run_dir);

	helper::ReportGuard report(run_dir);
	if(!report) return;

	report << "# Active Test Suite Report\n\n";
	report << "Tests whether a monitor-mode interface can both inject and receive ACKs (two-interface active TX test).\n\n";

	if(entries.empty()){ report << "No test results found.\n"; return; }

	report << "## Test Results\n\n";
	report << "| Test | TX Driver | RX Driver | Acked | Not Acked | Result |\n";
	report << "|------|-----------|-----------|:-----:|:---------:|:------:|\n";

	for(const auto &e: entries){
		const string name_cell = exists(run_dir / e.test_name / REPORT_NAME)
								? "[" + e.test_name + "](" + e.test_name + "/" + REPORT_NAME + ")"
								: e.test_name;
		const string result_link = "[" + string(e.success ? "PASSED" : "FAILED") + "](" + e.test_name + "/" +
				RESULT_NAME + ")";
		report << "| " << name_cell << " | " << e.tx_driver << " | " << e.rx_driver << " | " << e.acked << " | " <<
				e.not_acked << " | " << result_link << " |\n";
	}

	report << "\n## Summary\n\n";
	const size_t passed_count = ranges::count_if(entries, [](const auto &e){ return e.success; });
	report << "- Total Tests: " << entries.size() << "\n";
	report << "- Passed: " << passed_count << "\n";
	report << "- Failed: " << (entries.size() - passed_count) << "\n";
	report << "- Success Rate: " << fixed << setprecision(1) << (100.0 * static_cast<double>(passed_count) /
			static_cast<double>(entries.size())) << "%\n";
}
}
