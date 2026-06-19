#include "suite/scan/ap_info_wpa3_filler.h"

#include <filesystem>
#include <fstream>
#include "config/RunSuiteStatus.h"
#include "suite/result_helper.h"
#include "suite/suite_helper.h"

namespace wpa3_tester::suite::ap_info_wpa3_filler{
using namespace std;
using namespace filesystem;

ApInfoWpa3TestEntry ApInfoWpa3TestEntry::parse(const path &test_folder){
	auto e = helper::load_result_default<CsaTestEntry>(test_folder);
	ApInfoWpa3TestEntry e{};
	e.test_name = test_folder.filename().string();

	const auto j = helper::load_result_json(test_folder);
	if(!j) return e;

	e.mac = j->value("mac", "");
	e.ssid = j->value("ssid", "");
	e.mfp = j->value("mfp", "?");
	e.akm = j->value("akm", "");
	e.acm_triggered = j->value("acm_triggered", false);
	return e;
}

void generate_report(RunSuiteStatus &rss){
	const auto run_dir = rss.run_folder();
	const auto entries = helper::get_results_default<ApInfoWpa3TestEntry>(run_dir);

	helper::ReportGuard report(run_dir);
	if(!report) return;

	report << "# AP Info WPA3 Filler\n\n";

	if(entries.empty()){ report << "No test results found.\n"; return; }

	report << "| Test | MAC | SSID | MFP | AKM | ACM |\n";
	report << "|------|-----|------|-----|-----|-----|\n";
	for(const auto &e: entries){
		report << "| " << e.test_name << " | " << e.mac << " | " << e.ssid << " | " << e.mfp << " | " << e.akm <<
				" | " << (e.acm_triggered ? "yes" : "-") << " |\n";
	}
}
}
