#include "suite/suite_helper.h"

#include <fstream>
#include <memory>

#include "default.h"
#include "config/RunStatus.h"
#include "logger/log.h"
#include "system/utils.h"

namespace wpa3_tester::suite::helper{
using namespace std;
using namespace filesystem;

unique_ptr<RunStatus> load_test_rs(const path &test_folder){
	const auto config_path = test_folder / TEST_CONFIG_NAME;
	if(!exists(config_path)) throw runtime_error("test config file does not exist");
	auto rs = make_unique<RunStatus>();
	rs->config_path(config_path);
	rs->run_folder(test_folder);
	rs->load_actor_interface_mapping();
	return rs;
}

ofstream open_report(const path &report_path){
	const path resolved = is_directory(report_path) ? report_path / REPORT_NAME : report_path;
	ofstream report(resolved);
	if(!report.is_open()) log(LogLevel::ERROR, "Failed to create report: {}", resolved);
	return report;
}

void finalize_report(ofstream &report, const path &run_dir){
	report.close();
	set_public_perms(run_dir / REPORT_NAME);
	log(LogLevel::INFO, "Report written: {}", run_dir / REPORT_NAME);
}

vector<path> get_suite_test_folders(const path &suite_dir){
	vector<path> folders;
	const path last_run = suite_dir / LAST_RUN_DIR;
	if(!exists(last_run) || !is_directory(last_run)) return folders;
	error_code ec;
	for(const auto &entry: directory_iterator(last_run, ec)){
		if(!entry.is_directory()) continue;
		if(entry.path().filename() == TEST_SUITE_CONFIG_DIR) continue;
		folders.push_back(entry.path());
	}
	return folders;
}
}
