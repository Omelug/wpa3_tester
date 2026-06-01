#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <iomanip>

#include "config/RunSuiteStatus.h"
#include "logger/log.h"
#include "suite/DoS_soft/bl0ck/bl0ck_test_suites.h"
#include "system/utils.h"

namespace wpa3_tester::suite::bl0ck_test_suites{
using namespace std;
using namespace filesystem;
using namespace nlohmann;

void generate_ba_mac_gen_report(RunSuiteStatus &rss){
	log(LogLevel::INFO, "Generating BA_mac_gen test suite report");
	
	const auto run_dir = rss.run_folder();
	if(!exists(run_dir)){
		log(LogLevel::ERROR, "Run folder not found: {}", run_dir.string());
		return;
	}
	
	// Collect test results
	vector<tuple<string, string, string, string, bool>> test_results;
	
	// Iterate through each test folder
	for(const auto &entry: directory_iterator(run_dir)){
		if(!entry.is_directory()) continue;
		
		const auto test_folder = entry.path();
		const auto result_json = test_folder / "result.json";
		
		if(!exists(result_json)) continue;
		
		try{
			// Read result.json
			ifstream result_file(result_json);
			json result_data = json::parse(result_file);
			result_file.close();
			
			bool passed = result_data.value("passed", false);
			
			// Try to extract driver info from test name or config
			string ap_driver = "?";
			string client_driver = "?";
			string attacker_driver = "?";
			string ap_mac = test_folder.filename().string();
			
			// Try to read config to extract driver info
			const auto config_path = test_folder / "config.yaml";
			if(exists(config_path)){
				try{
					ifstream cfg(config_path);
					json cfg_data = json::parse(cfg);
					cfg.close();
					
					if(cfg_data.contains("actors")){
						auto &actors = cfg_data["actors"];
						if(actors.contains("access_point") && actors["access_point"].contains("selection")){
							ap_driver = actors["access_point"]["selection"].value("driver", "?");
						}
						if(actors.contains("client") && actors["client"].contains("selection")){
							client_driver = actors["client"]["selection"].value("driver", "?");
						}
						if(actors.contains("attacker") && actors["attacker"].contains("selection")){
							attacker_driver = actors["attacker"]["selection"].value("driver", "?");
						}
					}
				} catch(...){
					// Use defaults if config parsing fails
				}
			}
			
			test_results.emplace_back(ap_mac, ap_driver, client_driver, attacker_driver, passed);
		} catch(const exception &e){
			log(LogLevel::WARNING, "Failed to parse result.json in {}: {}", test_folder.string(), e.what());
		}
	}
	
	// Generate report
	ofstream report(run_dir / "report.md");
	if(!report.is_open()){
		log(LogLevel::ERROR, "Failed to create report.md");
		return;
	}
	
	report << "# BA MAC Generator Test Suite Report\n\n";
	report << "Summary of Bl0ck BA attack tests across different driver combinations.\n\n";
	
	if(test_results.empty()){
		report << "No test results found.\n";
		report.close();
		return;
	}
	
	// Generate results table
	report << "## Test Results\n\n";
	report << "| AP MAC | AP Driver | Client Driver | Attacker Driver | Result |\n";
	report << "|--------|-----------|---------------|-----------------|--------|\n";
	
	for(const auto &[ap_mac, ap_drv, cli_drv, att_drv, passed]: test_results){
		const string result_str = passed ? "✅ PASSED" : "❌ FAILED";
		report << "| " << ap_mac << " | " << ap_drv << " | " << cli_drv << " | " 
			   << att_drv << " | " << result_str << " |\n";
	}

	report << "\n## Summary\n\n";
	size_t passed_count = ranges::count_if(test_results, [](const auto &r){ return get<4>(r); });
	report << "- **Total Tests:** " << test_results.size() << "\n";
	report << "- **Passed:** " << passed_count << "\n";
	report << "- **Failed:** " << (test_results.size() - passed_count) << "\n";
	report << "- **Success Rate:** " << fixed << setprecision(1)
		   << (100.0 * passed_count / test_results.size()) << "%\n";
	
	report.close();
	set_public_perms(run_dir / "report.md");
	log(LogLevel::INFO, "BA_mac_gen report generated: {}", (run_dir / "report.md").string());
}
}
