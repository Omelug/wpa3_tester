#include "suite/suite_helper.h"

#include <fstream>
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

map<string, string> load_test_drivers(const path &test_folder) {
	map<string, string> drivers;
	const auto config_path = test_folder / "test_config.yaml";
	if(!exists(config_path)) return drivers;
	RunStatus rs{};
	rs.config_path(config_path);
	rs.run_folder(test_folder);
	rs.load_actor_interface_mapping();
	for(const auto &[name, actor] : rs.actors)
		drivers[name] = actor->get_or(SK::driver_name, "?");
	return drivers;
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

}