#include <filesystem>
#include <fstream>
#include <iomanip>

#include "config/RunStatus.h"
#include "config/RunSuiteStatus.h"
#include "logger/log.h"
#include "suite/DoS_soft/bl0ck/bl0ck_test_suites.h"
#include "suite/suite_helper.h"
#include "system/utils.h"

namespace wpa3_tester::suite::bl0ck_test_suites{
using namespace std;
using namespace filesystem;
using namespace nlohmann;

Bl0ckTestEntry parse_test_folder(const path &test_folder){
	Bl0ckTestEntry e;
	e.name = test_folder.filename().string();

	if(const auto result = helper::load_result_json(test_folder))
		e.disconnected = result->value("disconnect_count",0) > 0;

	const auto cfg_path = test_folder / "test_config.yaml";
	if(exists(cfg_path)){
		RunStatus rs{};
		rs.config_path(cfg_path);
		rs.run_folder(test_folder);
		rs.load_actor_interface_mapping();

		if(const auto it = rs.actors.find("access_point"); it != rs.actors.end()){
			e.ap_mac    = it->second->get_or(SK::mac,    "");
			e.ap_source = it->second->get_or(SK::source, "");
		}
		if(const auto it = rs.actors.find("client"); it != rs.actors.end()){
			e.client_mac    = it->second->get_or(SK::mac,    "");
			e.client_source = it->second->get_or(SK::source, "");
		}
		if(const auto it = rs.actors.find("attacker"); it != rs.actors.end()){
			e.attacker_mac    = it->second->get_or(SK::mac,         "");
			e.attacker_driver = it->second->get_or(SK::driver_name, "");
		}

		try{
			const auto cfg = YAML::LoadFile(cfg_path.string());
			if(cfg["attack_config"] && cfg["attack_config"]["attack_variant"])
				e.attack_variant = cfg["attack_config"]["attack_variant"].as<string>();
		} catch(...){}
	}

	return e;
}

void generate_bl0ck_mac_gen_report(RunSuiteStatus &rss){
	log(LogLevel::INFO, "Generating bl0ck mac_gen test suite report");

	const auto run_dir = rss.run_folder();
	if(!exists(run_dir)){
		log(LogLevel::ERROR, "Run folder not found: {}", run_dir);
		return;
	}

	auto entries = helper::collect_entries_nested(run_dir, [](const path &p, const path &rel) {
		auto e = parse_test_folder(p);
		e.name = rel.string();
		return e;
	});

	auto report = helper::open_report(run_dir / "report.md");
	if(!report.is_open()) return;

	report << "# Bl0ck MAC Generator Test Suite Report\n\n";
	report << "Summary of Bl0ck attack tests across different driver combinations.\n\n";

	if(entries.empty()){
		report << "No test results found.\n";
		report.close();
		return;
	}

	report << "## Test Results\n\n";
	report << "| Test | AP MAC | Client MAC | Attacker (driver) | Variant | Result |\n";
	report << "|------|--------|------------|-------------------|---------|--------|\n";

	size_t passed_count = 0;
	for(const auto &e: entries){
		if(e.disconnected.value()) ++passed_count;
		const string name_cell   = exists(run_dir / e.name / "report.md")
			? "[" + e.name + "](" + e.name + "/report.md)" : e.name;
		const string result_link = "[" + string(e.disconnected.value() ? "PASSED" : "FAILED") + "](" + e.name + "/result.json)";
		report << "| " << name_cell << " | " << e.ap_mac << " | " << e.client_mac << " | "
			   << e.attacker_mac << " (" << e.attacker_driver << ") | "
			   << (e.attack_variant.empty() ? "?" : e.attack_variant) << " | " << result_link << " |\n";
	}

	report << "\n## Summary\n\n";
	report << "- Total Tests: " << entries.size() << "\n";
	report << "- Passed: " << passed_count << "\n";
	report << "- Failed: " << (entries.size() - passed_count) << "\n";
	report << "- Success Rate: " << fixed << setprecision(1)
		   << (100.0 * passed_count / entries.size()) << "%\n";

	report.close();
	set_public_perms(run_dir / "report.md");
	log(LogLevel::INFO, "Bl0ck mac_gen report generated: {}", (run_dir / "report.md").string());
}
}