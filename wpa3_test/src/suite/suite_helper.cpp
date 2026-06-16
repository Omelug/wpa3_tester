#include "suite/suite_helper.h"

#include <fstream>
#include <memory>
#include "config/RunStatus.h"
#include "logger/log.h"

namespace wpa3_tester::suite::helper {
using namespace std;
using namespace filesystem;
using json = nlohmann::json;

optional<json> load_result_json(const path &test_folder) {
	const auto result_json = test_folder / "result.json";
	if(!exists(result_json)) return nullopt;
	ifstream rf(result_json);
	return json::parse(rf);
}

unique_ptr<RunStatus> load_test_rs(const path &test_folder) {
	const auto config_path = test_folder / "test_config.yaml";
	if(!exists(config_path)) throw std::runtime_error("test config file does not exist");
	auto rs = make_unique<RunStatus>();
	rs->config_path(config_path);
	rs->run_folder(test_folder);
	rs->load_actor_interface_mapping();
	return rs;
}


string get_driver(const map<string, string> &drivers, const string &actor) {
	const auto it = drivers.find(actor);
	return it != drivers.end() ? it->second : "?";
}

ofstream open_report(const path &report_path) {
	ofstream report(report_path);
	if(!report.is_open())
		log(LogLevel::ERROR, "Failed to create report: {}", report_path.string());
	return report;
}

vector<path> get_suite_test_folders(const path &suite_dir) {
	vector<path> folders;
	const path last_run = suite_dir / "last_run";
	if(!exists(last_run) || !is_directory(last_run)) return folders;
	error_code ec;
	for(const auto &entry : directory_iterator(last_run, ec)){
		if(!entry.is_directory()) continue;
		if(entry.path().filename() == "test_config") continue;
		folders.push_back(entry.path());
	}
	return folders;
}

}