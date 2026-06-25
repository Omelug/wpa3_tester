#include "suite/scan/ap_info_wpa3_filler.h"

#include <filesystem>
#include "config/RunSuiteStatus.h"
#include "logger/report.h"
#include "overview/html_guard.h"
#include "suite/result_helper.h"
#include "suite/suite_helper.h"

namespace wpa3_tester::suite::ap_info_wpa3_filler{
using namespace std;
using namespace filesystem;

ApInfoWpa3TestEntry ApInfoWpa3TestEntry::parse(const path &test_folder){
	auto e = helper::load_result_default<ApInfoWpa3TestEntry>(test_folder);
	e.test_name = test_folder.filename().string();
	return e;
}

void ApInfoWpa3TestEntry::render_table(overview::HtmlGuard &f,
                                       const vector<path> &folders,
                                       const path & /*page_dir*/) {
	f << "        <table class=\"aggregate\">\n"
	  << "            <thead><tr>"
	  << "<th>Test</th><th>MAC</th><th>SSID</th><th>MFP</th><th>AKM</th><th>ACM triggered</th>"
	  << "</tr></thead>\n            <tbody>\n";
	for (const auto &p : folders) {
		const auto e = parse(p);
		f << "                <tr>\n"
		  << "                    <td>" << e.test_name << "</td>\n"
		  << "                    <td>" << e.mac << "</td>\n"
		  << "                    <td>" << e.ssid << "</td>\n"
		  << "                    <td>" << e.mfp << "</td>\n"
		  << "                    <td>" << e.akm << "</td>\n"
		  << "                    <td>" << e.acm_triggered << "</td>\n"
		  << "                </tr>\n";
	}
	f << "            </tbody>\n        </table>\n";
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
