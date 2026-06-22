#include "attacks/DoS_soft/bl0ck/bl0ck.h"

#include <cassert>
#include <nlohmann/json.hpp>

#include "config/RunStatus.h"
#include "logger/report.h"
#include "observer/iperf_wrapper.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester::bl0ck_attack{
using namespace std;
using namespace filesystem;
using namespace Tins;
using namespace chrono;

void generate_report(const RunStatus &rs, const Bl0ckResult &result, const path &attacker_graph,
					const path &client_graph
){
	report::ReportGuard report(rs.run_folder());
	if(!report) return;

	const string variant = rs.config().at("attack_config").value("attack_variant", "?");
	report << "# Bl0ck DoS Attack (" << variant << ")\n\n";
	report << "Bl0ck sends malformed Block-Acknowledgement frames to force the AP/STA to drop the BA session, "
			"causing the client to disconnect.\n\n";
	report << "Rewrite of python PoC: https://github.com/efchatz/Bl0ck/tree/main?tab=readme-ov-file\n";

	report::attack_config_table(report, rs);
	report::attack_mapping_table(report, rs);

	// ----- result
	report << "## Test Result\n\n";
	report << "| Metric | Value |\n|--------|-------|\n";
	//report << "| **Result** | **" << (result.passed ? "PASSED" : "FAILED") << "** |\n";
	report << "| Disconnections | " << result.disconnect_count << " |\n";

	if(result.reconnect_times_ms.empty()){
		report << "| Reconnect time | n/a |\n";
	} else{
		for(size_t i = 0; i < result.reconnect_times_ms.size(); ++i) report << "| Reconnect time [" << i << "] | " <<
				static_cast<int>(result.reconnect_times_ms[i]) << " ms |\n";
		double avg = 0;
		for(const double t: result.reconnect_times_ms) avg += t;
		avg /= static_cast<double>(result.reconnect_times_ms.size());
		report << "| Avg reconnect time | " << static_cast<int>(avg) << " ms |\n";
	}
	report << "\n";

	// ----- graphs
	if(exists(attacker_graph)){
		report << "### Attacker capture\n";
		report << "![Attacker graph](" << attacker_graph << ")\n\n";
		report << "### Client capture (wpa\\_supplicant " << rs.config().at("actors").at("client").at("setup").
																at("program_config").value("version", "default") <<
				")\n";
	}
	if(exists(client_graph)){
		report << "![Client graph](" << client_graph << ")\n\n";
	}
	report << "---\n";
}
}
