#include "suite/scan/ap_info_wpa3_filler.h"

#include <filesystem>
#include <fstream>

#include "config/RunSuiteStatus.h"
#include "logger/log.h"
#include "suite/suite_helper.h"
#include "system/utils.h"

namespace wpa3_tester::suite::ap_info_wpa3_filler {
using namespace std;
using namespace filesystem;

ApInfoWpa3TestEntry parse_test_folder(const path &test_folder) {
	ApInfoWpa3TestEntry e{};
	e.test_name = test_folder.filename().string();

	const auto j = helper::load_result_json(test_folder);
	if (!j) return e;

	e.mac           = j->value("mac",           "");
	e.ssid          = j->value("ssid",          "");
	e.mfp           = j->value("mfp",           "?");
	e.akm           = j->value("akm",           "");
	e.acm_triggered = j->value("acm_triggered", false);
	return e;
}

vector<ApInfoWpa3TestEntry> get_results(const path &run_dir) {
	vector<ApInfoWpa3TestEntry> entries;
	for (const auto &dir_entry : directory_iterator(run_dir)) {
		if (!dir_entry.is_directory()) continue;
		if (dir_entry.path().filename() == "test_config") continue;
		entries.push_back(parse_test_folder(dir_entry.path()));
	}
	ranges::sort(entries, [](const auto &a, const auto &b) { return a.test_name < b.test_name; });
	return entries;
}

void generate_report(RunSuiteStatus &rss) {
	const auto run_dir = rss.run_folder();
	const auto entries = get_results(run_dir);

	auto report = helper::open_report(run_dir / "report.md");
	if (!report.is_open()) return;

	report << "# AP Info WPA3 Filler\n\n";

	if (entries.empty()) {
		report << "No test results found.\n";
		report.close();
		return;
	}

	report << "| Test | MAC | SSID | MFP | AKM | ACM |\n";
	report << "|------|-----|------|-----|-----|-----|\n";
	for (const auto &e : entries) {
		report << "| " << e.test_name
		       << " | " << e.mac
		       << " | " << e.ssid
		       << " | " << e.mfp
		       << " | " << e.akm
		       << " | " << (e.acm_triggered ? "yes" : "-")
		       << " |\n";
	}

	report.close();
	set_public_perms(run_dir / "report.md");
	log(LogLevel::INFO, "ap_info_wpa3_filler report generated: {}", (run_dir / "report.md").string());
}

}
