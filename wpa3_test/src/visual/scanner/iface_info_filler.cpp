#include "suite/scan/iface_info_filler.h"

#include <filesystem>
#include <fstream>

#include "default.h"
#include "attacks/scanner/iface_info.h"
#include "config/RunStatus.h"
#include "config/RunSuiteStatus.h"
#include "logger/devices.h"
#include "logger/report.h"
#include "suite/suite_helper.h"

namespace wpa3_tester::suite::iface_info_filler{
using namespace std;
using namespace filesystem;

IfaceInfoTestEntry IfaceInfoTestEntry::parse(const path &test_folder){
	IfaceInfoTestEntry e{};
	e.test_name = test_folder.filename().string();

	const auto config_path = test_folder / TEST_CONFIG_NAME;
	if(exists(config_path)){
		RunStatus rs{};
		rs.config_path(config_path);
		rs.run_folder(test_folder);
		rs.load_actor_interface_mapping();
		iface_info::stats_attack(rs);
		try{ report::add_device(rs.get_actor("scanner")); } catch(...){}

		ifstream f(test_folder / "result.txt");
		if(f.is_open()) e.hw_summary = string{istreambuf_iterator(f), {}};
		else e.hw_summary = "?";
	} else{
		e.hw_summary = "?";
	}

	for(const auto &f: directory_iterator(test_folder)){
		const auto fn = f.path().filename().string();
		if(fn.starts_with("iface_report_") && fn.ends_with(".md")){
			e.report_md = f.path();
			break;
		}
	}

	return e;
}

void generate_report(RunSuiteStatus &rss){
	const auto run_dir = rss.run_folder();
	const auto entries = helper::get_results_default<IfaceInfoTestEntry>(run_dir);

	report::ReportGuard r(run_dir);
	if(!r) return;

	r << "# Interface Info\n\n";

	if(entries.empty()){ r << "No test results found.\n"; return; }

	r << "| Test | Info  | Report |\n";
	r << "|------|-------|--------|\n";

	for(const auto &e: entries){
		r << "| "
			<< e.test_name << " | "
			<< e.hw_summary << " | "
			<< report::link("report", e.report_md, run_dir) << " |\n";
	}
}
}
