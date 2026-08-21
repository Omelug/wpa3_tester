#include "visual/scan/ap_info_wpa3_filler.h"

#include <filesystem>
#include "config/RunSuiteStatus.h"
#include "logger/report.h"
#include "overview/html_guard.h"
#include "overview/html_utils.h"
#include "visual/result_helper.h"
#include "visual/suite_helper.h"

namespace wpa3_tester::visual::ap_info_wpa3_filler{
using namespace std;
using namespace filesystem;

ApInfoWpa3TestEntry ApInfoWpa3TestEntry::parse(const path &test_folder){
	auto e = helper::load_result_default<ApInfoWpa3TestEntry>(test_folder);
	e.test_name = test_folder.filename().string();
	return e;
}

void ApInfoWpa3TestEntry::render_table(overview::HtmlGuard &f, const string &title,
	const path &suite_data_dir , const path &){
	helper::div_card<ApInfoWpa3TestEntry>(f, title, suite_data_dir, [&](overview::HtmlGuard& hg,
		const std::vector<ApInfoWpa3TestEntry>& entries) {

		HtmlPathTable t(hg, entries);

		#define COL(name, body) col(name, [&]( [[maybe_unused]] const auto& e) { f << body; })
		t.build([&](auto col) {
			COL("Test",                 &ApInfoWpa3TestEntry::test_name);
			COL("MAC",                  &ApInfoWpa3TestEntry::mac);
			COL("SSID",                 &ApInfoWpa3TestEntry::ssid);
			COL("MFP",                  &ApInfoWpa3TestEntry::mfp);
			COL("AKM",                  &ApInfoWpa3TestEntry::akm);
			COL("ACM triggered",        &ApInfoWpa3TestEntry::acm_triggered);
		})->render();
		#undef COL
	});
}

void generate_report(RunSuiteStatus &rss){
	const auto run_dir = rss.run_folder();
	const auto entries = helper::get_results_default<ApInfoWpa3TestEntry>(run_dir);

	report::ReportGuard r(run_dir);
	if(!r) return;

	r << "# AP Info WPA3 Filler\n\n";
	if(entries.empty()){ r << "No test results found.\n"; return; }

	r << "| Test | MAC | SSID | MFP | AKM | ACM | Stations |\n";
	r << "|------|-----|------|-----|-----|-----|----------|\n";
	for(const auto &e: entries){

		string stas;
		for(const auto &s: e.stations) stas += (stas.empty() ? "" : "<br>") + s;

		r << "| "
		<< e.test_name << " | "
		<< report::device(e.mac) << " | "
		<< e.ssid << " | "
		<< e.mfp << " | "
		<< e.akm << " | "
		<< e.acm_triggered << " | "
		<< stas << " |\n";
	}
}
}
