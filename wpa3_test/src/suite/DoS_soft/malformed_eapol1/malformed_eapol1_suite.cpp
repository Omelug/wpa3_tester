#include <filesystem>
#include <fstream>
#include <iomanip>
#include <nlohmann/json.hpp>

#include "suite/DoS_soft/malformed_eapol1/malformed_eapol1_suite.h"
#include "config/RunSuiteStatus.h"
#include "logger/log.h"
#include "suite/suite_helper.h"
#include "system/utils.h"

namespace wpa3_tester::suite::malformed_eapol1_filler {
using namespace std;
using namespace filesystem;
using namespace nlohmann;

MalformedEapol1TestEntry parse_test_folder(const path &test_folder) {
	MalformedEapol1TestEntry e{};
	e.test_name = test_folder.filename().string();

	const auto result = helper::load_result_json(test_folder);
	if (!result) return e;

	const auto drv    = helper::load_test_drivers(test_folder);
	e.disconnect_count = result->value("disconnect_count", 0);
	e.passed           = e.disconnect_count > 0;
	e.sta_graph        = test_folder / "observer" / "tshark" / "client_graph.png";
	e.ap_graph         = test_folder / "observer" / "tshark" / "access_point_graph.png";
	e.ap_driver        = helper::get_driver(drv, "access_point");
	e.client_driver    = helper::get_driver(drv, "client");
	e.attacker_driver  = helper::get_driver(drv, "attacker");
	return e;
}

vector<MalformedEapol1TestEntry> get_results(const path &run_dir) {
	vector<MalformedEapol1TestEntry> entries;
	for (const auto &entry : directory_iterator(run_dir)) {
		if (!entry.is_directory()) continue;
		auto e = parse_test_folder(entry.path());
		if (!e.passed.has_value()) continue;
		entries.push_back(std::move(e));
	}
	ranges::sort(entries, [](const MalformedEapol1TestEntry &a, const MalformedEapol1TestEntry &b) {
		return a.test_name < b.test_name;
	});
	return entries;
}

void generate_report(RunSuiteStatus &rss) {
	log(LogLevel::INFO, "Generating malformed_eapol1 suite report");

	const auto run_dir = rss.run_folder();
	if (!exists(run_dir)) {
		log(LogLevel::ERROR, "Run folder not found: {}", run_dir);
		return;
	}

	const auto entries = get_results(run_dir);

	const auto report_path = run_dir / "report.md";
	auto report = helper::open_report(report_path);
	if (!report.is_open()) return;

	report << "# Malformed EAPOL-1 Test Suite Report\n\n";
	report << "Tests whether a malformed EAPOL Key frame (invalid tag length) causes client disconnection.\n\n";

	if (entries.empty()) {
		report << "No test results found.\n";
		report.close();
		return;
	}

	report << "## Results\n\n";
	report << "| Test | AP Driver | Client Driver | Attacker Driver | Disconnected | Disconnects | Graphs |\n";
	report << "|------|-----------|---------------|-----------------|:------------:|:-----------:|--------|\n";

	int passed_count = 0;
	for (const auto &e : entries) {
		if (e.passed.value()) ++passed_count;

		string graphs;
		if (exists(e.sta_graph))
			graphs += "[STA](" + e.sta_graph.string() + ")";
		if (exists(e.ap_graph)) {
			if (!graphs.empty()) graphs += " ";
			graphs += "[AP](" + e.ap_graph.string() + ")";
		}
		if (graphs.empty()) graphs = "-";

		const string name_cell = exists(run_dir / e.test_name / "report.md")
			? "[" + e.test_name + "](" + e.test_name + "/report.md)" : e.test_name;
		const string disc_link = "[" + string(e.passed.value() ? "yes" : "no") + "](" + e.test_name + "/result.json)";
		report << "| " << name_cell
		       << " | " << e.ap_driver
		       << " | " << e.client_driver
		       << " | " << e.attacker_driver
		       << " | " << disc_link
		       << " | " << e.disconnect_count
		       << " | " << graphs
		       << " |\n";
	}

	report << "\n## Summary\n\n";
	report << "- Total: " << entries.size() << "\n";
	report << "- Disconnected (passed): " << passed_count << "\n";
	report << "- Not disconnected: " << (entries.size() - passed_count) << "\n";
	report << "- Success rate: " << fixed << setprecision(1)
	       << (100.0 * passed_count / static_cast<double>(entries.size())) << "%\n";

	report.close();
	set_public_perms(report_path);
	log(LogLevel::INFO, "Report written: {}", report_path.string());
}

}