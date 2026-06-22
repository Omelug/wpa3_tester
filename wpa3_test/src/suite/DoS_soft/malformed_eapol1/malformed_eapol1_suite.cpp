#include <filesystem>
#include <fstream>
#include <iomanip>
#include <nlohmann/json.hpp>

#include "default.h"
#include "suite/DoS_soft/malformed_eapol1/malformed_eapol1_suite.h"
#include "config/RunSuiteStatus.h"
#include "logger/report.h"
#include "suite/result_helper.h"
#include "suite/suite_helper.h"

namespace wpa3_tester::suite::malformed_eapol1_filler{
using namespace std;
using namespace filesystem;
using namespace nlohmann;

MalformedEapol1TestEntry MalformedEapol1TestEntry::parse(const path &test_folder){
	auto e = helper::load_result_default<MalformedEapol1TestEntry>(test_folder);
	e.test_name = test_folder.filename().string();

	const auto rs = helper::load_test_rs(test_folder);
	//FIXME static paths
	e.sta_graph = test_folder / "observer" / "tshark" / "client_graph.png";
	e.ap_graph = test_folder / "observer" / "tshark" / "access_point_graph.png";
	e.ap_driver = rs->get_actor("access_point").get(SK::driver_name);
	e.client_driver = rs->get_actor("client").get(SK::driver_name);
	e.attacker_driver = rs->get_actor("attacker").get(SK::driver_name);
	return e;
}

void generate_report(RunSuiteStatus &rss){
	const auto entries = helper::get_results_default<MalformedEapol1TestEntry>(rss.run_folder());

	const auto report_path =  rss.run_folder() / REPORT_NAME;
	report::ReportGuard report(rss.run_folder());
	if(!report) return;

	report << "# Malformed EAPOL-1 Test Suite Report\n\n";
	report << "Tests whether a malformed EAPOL Key frame (invalid tag length) causes client disconnection.\n\n";

	if(entries.empty()){ report << "No test results found.\n"; return; }

	report << "## Results\n\n";
	report << "| Test | AP Driver | Client Driver | Attacker Driver | Disconnected (count) | Graphs |\n";
	report << "|------|-----------|---------------|-----------------|:--------------------:|:------:|\n";

	int passed_count = 0;
	for(const auto &e: entries){
		if(e.disconnect_count > 0) ++passed_count;

		string graphs;
		if(exists(e.sta_graph)) graphs += "[STA](" + e.sta_graph.string() + ")";
		if(exists(e.ap_graph)){
			if(!graphs.empty()) graphs += " ";
			graphs += "[AP](" + e.ap_graph.string() + ")";
		}
		if(graphs.empty()) graphs = "-";

		const string name_cell = exists(rss.run_folder() / e.test_name / REPORT_NAME)
								? "[" + e.test_name + "](" + e.test_name + "/" + REPORT_NAME + ")"
								: e.test_name;
		const string disc_link = "[" + string((e.disconnect_count > 0) ? "yes" : "no") + "](" + e.test_name + "/" +
				RESULT_NAME + ")";
		report << "| " << name_cell << " | " << e.ap_driver << " | " << e.client_driver << " | " <<
				e.attacker_driver << " | " << disc_link << "(" << e.disconnect_count << ")"
				<< " | " << graphs << " |\n";
	}

	report << "\n## Summary\n\n";
	report << "- Total: " << entries.size() << "\n";
	report << "- Disconnected (passed): " << passed_count << "\n";
	report << "- Not disconnected: " << (entries.size() - passed_count) << "\n";
	report << "- Success rate: " << fixed << setprecision(1) << (100.0 * passed_count /
			static_cast<double>(entries.size())) << "%\n";
}
}
