#include <filesystem>
#include <fstream>
#include <iomanip>
#include <nlohmann/json.hpp>

#include "config/RunStatus.h"
#include "config/RunSuiteStatus.h"
#include "logger/log.h"
#include "suite/DoS_soft/malformed_eapol1/malformed_eapol1_suite.h"
#include "system/utils.h"

namespace wpa3_tester::suite::malformed_eapol1_filler{
using namespace std;
using namespace filesystem;
using namespace nlohmann;

struct TestEntry {
	string test_name;
	string ap_driver;
	string client_driver;
	string attacker_driver;
	int    disconnect_count;
	path   sta_graph;
	path   ap_graph;
};

void generate_report(RunSuiteStatus &rss){
	log(LogLevel::INFO, "Generating malformed_eapol1 suite report");

	const auto run_dir = rss.run_folder();
	if(!exists(run_dir)){
		log(LogLevel::ERROR, "Run folder not found: {}", run_dir.string());
		return;
	}

	vector<TestEntry> entries;

	for(const auto &entry: directory_iterator(run_dir)){
		if(!entry.is_directory()) continue;

		const auto test_folder = entry.path();
		const auto result_json = test_folder / "result.json";
		if(!exists(result_json)) continue;

		ifstream rf(result_json);
		const json result = json::parse(rf);
		rf.close();

		TestEntry e;
		e.test_name       = test_folder.filename().string();
		e.disconnect_count= result.value("disconnect_count", 0);
		e.sta_graph       = test_folder / "observer" / "tshark" / "client_graph.png";
		e.ap_graph        = test_folder / "observer" / "tshark" / "access_point_graph.png";
		e.ap_driver       = "?";
		e.client_driver   = "?";
		e.attacker_driver = "?";

		const auto config_path = test_folder / "test_config.yaml";
		if(exists(config_path)){
			RunStatus rs{};
			rs.config_path(config_path);
			rs.run_folder(test_folder);
			rs.load_actor_interface_mapping();

			if(auto it = rs.actors.find("access_point"); it != rs.actors.end())
				e.ap_driver = it->second->get_or(SK::driver_name, "?");
			if(auto it = rs.actors.find("client"); it != rs.actors.end())
				e.client_driver = it->second->get_or(SK::driver_name, "?");
			if(auto it = rs.actors.find("attacker"); it != rs.actors.end())
				e.attacker_driver = it->second->get_or(SK::driver_name, "?");
		}

		entries.push_back(std::move(e));
	}

	sort(entries.begin(), entries.end(),
		 [](const TestEntry &a, const TestEntry &b){ return a.test_name < b.test_name; });

	const auto report_path = run_dir / "report.md";
	ofstream report(report_path);
	set_public_perms(report_path);
	if(!report.is_open()){
		log(LogLevel::ERROR, "Failed to create report.md");
		return;
	}

	report << "# Malformed EAPOL-1 Test Suite Report\n\n";
	report << "Tests whether a malformed EAPOL Key frame (invalid tag length) causes client disconnection.\n\n";

	if(entries.empty()){
		report << "No test results found.\n";
		report.close();
		return;
	}

	report << "## Results\n\n";
	report << "| Test | AP Driver | Client Driver | Attacker Driver | Disconnected | Disconnects | Reports |\n";
	report << "|------|-----------|---------------|-----------------|:------------:|:-----------:|---------|\n";

	int passed_count = 0;
	for(const auto &e: entries){
		if(e.disconnect_count > 0) ++passed_count;

		string links;
		if(exists(e.sta_graph))
			links += "[STA](" + e.sta_graph.string() + ")";
		if(exists(e.ap_graph)){
			if(!links.empty()) links += " ";
			links += "[AP](" + e.ap_graph.string() + ")";
		}
		if(links.empty()) links = "-";

		report << "| " << e.test_name

			   << " | " << e.ap_driver
			   << " | " << e.client_driver
			   << " | " << e.attacker_driver
			   << " | " << e.disconnect_count
			   << " | " << links
			   << " |\n";
	}

	report << "\n## Summary\n\n";
	report << "- **Total:** " << entries.size() << "\n";
	report << "- **Disconnected (passed):** " << passed_count << "\n";
	report << "- **Not disconnected:** " << (entries.size() - passed_count) << "\n";
	report << "- **Success rate:** " << fixed << setprecision(1)
		   << (100.0 * passed_count / static_cast<double>(entries.size())) << "%\n";

	report.close();
	log(LogLevel::INFO, "Report written: {}", report_path.string());
}

}