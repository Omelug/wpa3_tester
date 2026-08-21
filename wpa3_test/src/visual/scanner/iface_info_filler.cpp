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
#include "system/driver_diagnostics.h"

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

		try{
			const auto result = rs.load_result();
			e.driver_summary = driver_diag::summarize_driver_specific(
				result.value("driver_specific", nlohmann::json::object()));
			if(result.contains("channel_switch")){
				const auto &cs = result["channel_switch"];
				e.channel_switch_ok = cs.value("ok", false);
				e.channel_switch_ms = cs.value("ms", -1);
			}
			if(result.contains("netns_move")){
				const auto &nm = result["netns_move"];
				e.netns_move_ok = nm.value("ok", false);
				e.netns_move_ms = nm.value("ms", -1);
			}
			if(result.contains("netns_return"))
				e.netns_return_ms = result["netns_return"].value("ms", -1);
		} catch(...){ e.driver_summary = "?"; }

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

	r << "| Test | Info | Ch Switch | NetNS Move | Report |\n";
	r << "|------|------|-----------|------------|--------|\n";

	for(const auto &e: entries){
		string ch = "n/a";
		if(e.channel_switch_ok.has_value())
			ch = (e.channel_switch_ok.value() ? "ok " : "fail ") + to_string(e.channel_switch_ms.value_or(-1)) + "ms";

		string ns = "n/a";
		if(e.netns_move_ok.has_value()){
			ns = (e.netns_move_ok.value() ? "ok " : "fail ") + to_string(e.netns_move_ms.value_or(-1)) + "ms";
			if(e.netns_return_ms.has_value())
				ns += " / " + to_string(e.netns_return_ms.value()) + "ms";
		}

		r << "| "
			<< e.test_name << " | "
			<< e.hw_summary << " | "
			<< ch << " | "
			<< ns << " | "
			<< report::link("report", e.report_md) << " |\n";
	}
}
}
