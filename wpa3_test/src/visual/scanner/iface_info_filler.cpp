#include "visual/scan/iface_info_filler.h"

#include <filesystem>
#include <fstream>

#include "attacks/scanner/iface_info.h"
#include "config/RunStatus.h"
#include "config/RunSuiteStatus.h"
#include "default.h"
#include "logger/devices.h"
#include "logger/report.h"
#include "system/driver_diagnostics.h"
#include "visual/suite_helper.h"

namespace wpa3_tester::visual::iface_info_filler {
using namespace std;
using namespace filesystem;

IfaceInfoTestEntry IfaceInfoTestEntry::parse(const path &test_folder) {
	IfaceInfoTestEntry e{};
	e.test_name = test_folder.filename().string();

	const auto config_path = test_folder / TEST_CONFIG_NAME;
	if(exists(config_path)) {
		RunStatus rs{};
		rs.config_path(config_path);
		rs.run_folder(test_folder);
		rs.load_actor_interface_mapping();
		iface_info::stats_attack(rs);
		//try {
			report::add_device(rs.get_actor("scanner"));
		//} catch(...) {} //FIXME test

		ifstream f(test_folder / "result.txt");
		if(f.is_open())
			e.hw_summary = string{ istreambuf_iterator(f), {} };
		else
			e.hw_summary = "?";

		try {
			const auto result = rs.load_result();
			e.driver_summary =
					driver_diag::summarize_driver_specific(result.value("driver_specific", nlohmann::json::object()));
			if(result.contains("channel_switch")) {
				const auto &cs = result["channel_switch"];
				e.channel_switch_ok = cs.value("ok", false);
				e.channel_switch_us = cs.value("us", -1);
			}
			if(result.contains("netns_move")) {
				const auto &nm = result["netns_move"];
				e.netns_move_ok = nm.value("ok", false);
				e.netns_move_ms = nm.value("ms", -1);
			}
			if(result.contains("netns_return")) e.netns_return_ms = result["netns_return"].value("ms", -1);
			if(result.contains("sniff_iface_create")) {
				const auto &si = result["sniff_iface_create"];
				e.sniff_iface_ok = si.value("ok", false);
				e.sniff_iface_ms = si.value("ms", -1);
			}
			if(result.contains("start_ap")) {
				const auto &ap = result["start_ap"];
				e.start_ap_ok = ap.value("ok", false);
				e.start_ap_ms = ap.value("ms", -1);
			}
		} catch(...) { e.driver_summary = "?"; }

	} else {
		e.hw_summary = "?";
	}

	for(const auto &f: directory_iterator(test_folder)) {
		const auto fn = f.path().filename().string();
		if(fn.starts_with("iface_report_") && fn.ends_with(".md")) {
			e.report_md = f.path();
			break;
		}
	}

	return e;
}

void generate_report(RunSuiteStatus &rss) {
	const auto run_dir = rss.run_folder();
	const auto entries = helper::get_results_default<IfaceInfoTestEntry>(run_dir);

	report::ReportGuard r(run_dir);
	if(!r) return;

	r << "# Interface Info\n\n";

	if(entries.empty()) {
		r << "No test results found.\n";
		return;
	}

	r << "| Test | Info | Ch Switch | NetNS Move | Sniff VIF | Start AP | Report |\n";
	r << "|------|------|-----------|------------|-----------|----------|--------|\n";

	for(const auto &e: entries) {
		string ch = "n/a";
		if(e.channel_switch_ok.has_value())
			ch = (e.channel_switch_ok.value() ? "ok " : "fail ") + to_string(e.channel_switch_us.value_or(-1)) + "us";

		string ns = "n/a";
		if(e.netns_move_ok.has_value()) {
			ns = (e.netns_move_ok.value() ? "ok " : "fail ") + to_string(e.netns_move_ms.value_or(-1)) + "ms";
			if(e.netns_return_ms.has_value()) ns += " / " + to_string(e.netns_return_ms.value()) + "ms";
		}

		string si = "n/a";
		if(e.sniff_iface_ok.has_value())
			si = (e.sniff_iface_ok.value() ? "ok " : "fail ") + to_string(e.sniff_iface_ms.value_or(-1)) + "ms";

		string ap = "n/a";
		if(e.start_ap_ok.has_value())
			ap = (e.start_ap_ok.value() ? "ok " : "fail ") + to_string(e.start_ap_ms.value_or(-1)) + "ms";

		r << "| " << e.test_name << " | " << e.hw_summary << " | " << ch << " | " << ns << " | "
		  << si << " | " << ap << " | " << report::link("report", e.report_md) << " |\n";
	}
}
}
