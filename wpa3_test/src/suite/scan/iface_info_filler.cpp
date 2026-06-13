#include "suite/scan/iface_info_filler.h"

#include <filesystem>
#include <fstream>

#include "attacks/scanner/iface_info.h"
#include "config/RunStatus.h"
#include "config/RunSuiteStatus.h"
#include "logger/log.h"
#include "suite/suite_helper.h"
#include "system/utils.h"

namespace wpa3_tester::suite::iface_info_filler {
using namespace std;
using namespace filesystem;

IfaceInfoTestEntry parse_test_folder(const path &test_folder) {
	IfaceInfoTestEntry e{};
	e.test_name = test_folder.filename().string();

	const auto config_path = test_folder / "test_config.yaml";
	if (exists(config_path)) {
		RunStatus rs{};
		rs.config_path(config_path);
		rs.run_folder(test_folder);
		rs.load_actor_interface_mapping();
		iface_info::stats_attack(rs);

		ifstream f(test_folder / "result.txt");
		if (f.is_open())
			e.hw_summary = string{istreambuf_iterator(f), {}};
		else
			e.hw_summary = "?";
	} else {
		e.hw_summary = "?";
	}

	for (const auto &f : directory_iterator(test_folder)) {
		const auto fn = f.path().filename().string();
		if (fn.starts_with("iface_report_") && fn.ends_with(".md")) {
			e.report_md = f.path();
			break;
		}
	}

	return e;
}

vector<IfaceInfoTestEntry> get_results(const path &run_dir) {
	vector<IfaceInfoTestEntry> entries;
	for (const auto &dir_entry : directory_iterator(run_dir)) {
		if (!dir_entry.is_directory()) continue;
		if (dir_entry.path().filename() == "test_config") continue;
		entries.push_back(parse_test_folder(dir_entry.path()));
	}
	ranges::sort(entries, [](const auto &a, const auto &b) { return a.test_name < b.test_name; });
	return entries;
}

void generate_report(RunSuiteStatus &rss) {
	const auto run_dir = rss.run_folder();
	const auto entries = get_results(run_dir);

	auto report = helper::open_report(run_dir / "report.md");
	if (!report.is_open()) return;

	report << "# Interface Info\n\n";

	if (entries.empty()) {
		report << "No test results found.\n";
		report.close();
		return;
	}

	report << "| Test | Info | Report |\n";
	report << "|------|---------|--------|\n";

	for (const auto &e : entries) {
		string report_link = "-";
		if (!e.report_md.empty()) {
			const auto rel = e.report_md.lexically_relative(run_dir);
			report_link = "[report](" + rel.string() + ")";
		}
		report << "| " << e.test_name
		       << " | " << e.hw_summary
		       << " | " << report_link
		       << " |\n";
	}

	report.close();
	set_public_perms(run_dir / "report.md");
	log(LogLevel::INFO, "iface_info suite report generated: {}", (run_dir / "report.md"));
}

}
