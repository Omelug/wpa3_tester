#include <filesystem>
#include <fstream>
#include <iomanip>
#include <nlohmann/json.hpp>

#include "suite/DoS_soft/channel_switch/channel_switch_rogueAP.h"
#include "config/RunStatus.h"
#include "config/RunSuiteStatus.h"
#include "ex_program/hostapd/hostapd_helper.h"
#include "logger/log.h"
#include "suite/suite_helper.h"
#include "system/utils.h"

namespace wpa3_tester::suite::channel_switch_rogueAP{
using namespace std;
using namespace filesystem;

CsaTestEntry parse_test_folder(const path &test_folder){
	CsaTestEntry e;
	e.name = test_folder.filename().string();

	if(const auto result = helper::load_result_json(test_folder)){
		e.passed = result->value("passed", false);
		if(result->contains("disconnected"))
			e.disconnected = result->at("disconnected").get<bool>();
		if(result->contains("ap_disconnected"))
			e.ap_disconnected = result->at("ap_disconnected").get<bool>();
		if(result->contains("rogue_ap_connected"))
			e.rogue_ap = result->at("rogue_ap_connected").get<bool>();
	}

	const auto cfg_path = test_folder / "test_config.yaml";
	if(exists(cfg_path)){
		RunStatus rs{};
		rs.config_path(cfg_path);
		rs.run_folder(test_folder);
		rs.load_actor_interface_mapping();

		if(const auto it = rs.actors.find("access_point"); it != rs.actors.end()){
			e.ap_mac    = it->second->get_or(SK::mac,    "");
			e.ap_source = it->second->get_or(SK::source, "");
			e.ap_ocv    = it->second[BK::OCV];
		}
		if(const auto it = rs.actors.find("client"); it != rs.actors.end()){
			e.client_mac    = it->second->get_or(SK::mac,    "");
			e.client_source = it->second->get_or(SK::source, "");
			e.client_ocv    = it->second[BK::OCV];
			e.client_mfp    = hostapd::get_mfp_from_supplicant(test_folder / "client_wpa_supplicant.conf");
		}
		if(const auto it = rs.actors.find("attacker"); it != rs.actors.end()){
			e.attacker_mac    = it->second->get_or(SK::mac,         "");
			e.attacker_driver = it->second->get_or(SK::driver_name, "");
		}
		if(const auto it = rs.actors.find("rogue_ap"); it != rs.actors.end()){
			e.rogue_ap_mac    = it->second->get_or(SK::mac,         "");
			e.rogue_ap_driver = it->second->get_or(SK::driver_name, "");
		}
	}

	const path tshark = test_folder / "observer" / "tshark";
	if(const auto p = tshark / "client_graph.png";       exists(p)) e.client_graph = p;
	if(const auto p = tshark / "access_point_graph.png"; exists(p)) e.ap_graph     = p;

	return e;
}

static string opt_bool(const optional<bool> &v){
	if(!v.has_value()) return "N/A";
	return v.value() ? "yes" : "no";
}

void generate_report(RunSuiteStatus &rss){
	log(LogLevel::INFO, "Generating CSA rogue AP test suite report");

	const auto run_dir = rss.run_folder();
	if(!exists(run_dir)){
		log(LogLevel::ERROR, "Run folder not found: {}", run_dir.string());
		return;
	}

	auto test_results = helper::collect_entries_nested(run_dir, [&run_dir](const path &p) {
		auto e = parse_test_folder(p);
		e.rel_path = relative(p, run_dir);
		return e;
	});

	auto report = helper::open_report(run_dir / "report.md");
	if(!report.is_open()) return;

	report << "# CSA Rogue AP Test Suite Report\n\n";
	report << "Summary of Channel Switch + Rogue AP downgrade attack tests.\n\n";

	if(test_results.empty()){
		report << "No test results found.\n";
		report.close();
		return;
	}

	report << "## Test Results\n\n";
	report << "| Test | AP MAC (source) | Client MAC (source) | Attacker MAC (driver) | Disconnected? (from_AP_view) ? | Rogue AP? | AP OCV / Client OCV | Client MFP | Result |\n";
	report << "|------|-----------------|---------------------|-----------------------|--------------------------------|-----------|---------------------|------------|--------|\n";

	for(const auto &e: test_results){
		const string rel = e.rel_path.string();
		const string name_cell   = exists(run_dir / e.rel_path / "report.md")
			? "[" + e.name + "](" + rel + "/report.md)" : e.name;
		const string result_link = "[" + string(e.passed.value() ? "PASSED" : "FAILED")
			+ "](" + rel + "/result.json)";
		const string ap_cell       = e.ap_mac       + " (" + e.ap_source + ")";
		const string client_cell   = e.client_mac   + " (" + e.client_source + ")";
		string attacker_cell = e.attacker_mac + " (" + e.attacker_driver + ")";
		if(!e.rogue_ap_mac.empty() || !e.rogue_ap_driver.empty())
			attacker_cell += "<br>" + e.rogue_ap_mac + " (" + e.rogue_ap_driver + ")";
		const string ocv_cell      = opt_bool(e.ap_ocv) + " / " + opt_bool(e.client_ocv);
		report << "| " << name_cell
			   << " | " << ap_cell
			   << " | " << client_cell
			   << " | " << attacker_cell
			   << " | " << opt_bool(e.disconnected) << " (" << opt_bool(e.ap_disconnected) << ")"
			   << " | " << opt_bool(e.rogue_ap)
			   << " | " << ocv_cell
			   << " | " << e.client_mfp
			   << " | " << result_link << " |\n";
	}

	report << "\n## Summary\n\n";
	const size_t passed_count = ranges::count_if(test_results, [](const auto &e){ return e.passed.value_or(false); });
	report << "- Total Tests: " << test_results.size() << "\n";
	report << "- Passed: "      << passed_count << "\n";
	report << "- Failed: "      << (test_results.size() - passed_count) << "\n";
	report << "- Success Rate: " << fixed << setprecision(1)
		   << (100.0 * passed_count / test_results.size()) << "%\n";

	report.close();
	set_public_perms(run_dir / "report.md");
	log(LogLevel::INFO, "CSA rogue AP report generated: {}", (run_dir / "report.md").string());
}
}