#include <filesystem>
#include <fstream>
#include <iomanip>
#include <nlohmann/json.hpp>

#include "suite/two_iface/active_test_filler.h"
#include "config/RunSuiteStatus.h"
#include "logger/log.h"
#include "suite/suite_helper.h"
#include "system/utils.h"

namespace wpa3_tester::suite::active_test_filler{
using namespace std;
using namespace filesystem;
using namespace nlohmann;

struct TestEntry {
	string test_name;
	string tx_driver;
	string rx_driver;
	int    acked;
	int    not_acked;
	bool   success;
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
		e.test_name  = test_folder.filename().string();
		e.acked      = result->value("acked", 0);
		e.not_acked  = result->value("not_acked", 0);
		e.success    = result->value("success", false);
		e.tx_driver  = helper::get_driver(drv, "transceiver");
		e.rx_driver  = helper::get_driver(drv, "receiver");
		entries.push_back(std::move(e));
	}

	ranges::sort(entries, [](const auto &a, const auto &b){ return a.test_name < b.test_name; });

	auto report = helper::open_report(run_dir / "report.md");
	if(!report.is_open()) return;

	report << "# Active Test Suite Report\n\n";
	report << "Tests whether a monitor-mode interface can both inject and receive ACKs (two-interface active TX test).\n\n";

	if(entries.empty()){
		report << "No test results found.\n";
		report.close();
		return;
	}

	report << "## Test Results\n\n";
	report << "| Test | TX Driver | RX Driver | Acked | Not Acked | Result |\n";
	report << "|------|-----------|-----------|:-----:|:---------:|:------:|\n";

	for(const auto &e: entries){
		report << "| " << e.test_name
			   << " | " << e.tx_driver
			   << " | " << e.rx_driver
			   << " | " << e.acked
			   << " | " << e.not_acked
			   << " | " << (e.success ? "PASSED" : "FAILED")
			   << " |\n";
	}

	report << "\n## Summary\n\n";
	const size_t passed_count = ranges::count_if(entries, [](const auto &e){ return e.success; });
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
