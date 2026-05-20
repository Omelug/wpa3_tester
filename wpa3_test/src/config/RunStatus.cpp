#include "config/RunStatus.h"
#include "system/utils.h"
#include <filesystem>
#include <optional>
#include "logger/error_log.h"
#include "logger/log.h"
#include <string>
#include <yaml-cpp/yaml.h>
#include "attacks/attacks.h"
#include "config/Observer_config.h"
#include "ex_program/external_actors/openwrt/OpenWrtConn.h"
#include "setup/config_parser.h"

namespace wpa3_tester{
using namespace std;
using namespace filesystem;

RunStatus::RunStatus(const string &config_path, string testName, const string &sub_folder){
	_config_path = config_path;
	if(!exists(config_path)){ throw config_err("Config not found: " + config_path); }

	if(testName.empty()){
		// load name from YAML if not name set
		const YAML::Node node = YAML::LoadFile(config_path);
		if(!node["name"] || !node["name"].IsScalar()){
			throw config_err("Config missing required string field 'name':" + config_path);
		}
		testName = node["name"].as<string>();
	}
	// add subfolder from test default
	string actual_sub_folder = ".";
	if(sub_folder.empty()){
		actual_sub_folder = relative_from("attack_config", config_path);
	}
	_run_folder = (BASE_FOLDER / actual_sub_folder / testName / "last_run").string();
	log(LogLevel::INFO, "Used config {}", config_path);
	_config = config_validation(_config_path);

	parse_run_config(_config, _run_config);
}

void RunStatus::clean(){
	process_manager.stop_all();
	actors.clear();
	observers.clear();
}

void RunStatus::execute(){
	globalRunStatus = this;

	if(exists(_run_folder)){
		if(_run_config.get_rewrite() == RewriteMode::none){
			log(LogLevel::DEBUG, "Skipping: {}", _run_folder.filename().string());
			return;
		}
		if(_run_config.get_rewrite() == RewriteMode::errors && !(exists(_run_folder / "errors.txt") || !exists(_run_folder / "done.txt"))){
			log(LogLevel::WARNING, "Skipping already successfully run test : {}", _run_folder.filename().string());
			return;
		}
		if(_run_config.get_delete_old()){ // remove -> no rewrite, better for debugging
			log(LogLevel::DEBUG, "Deleting old run folder: {}", _run_folder.filename().string());
			remove_all(_run_folder);
		}
	}

	// Ensure parent directories exist
	error_code ec;
	create_directories(_run_folder, ec);
	if(ec) throw run_err("Unable to create run base directory");

	// Initialize log file if save_log is enabled
	if(_run_config.get_save_log()){
		const path log_file = _run_folder / "logger" / "tester.log";
		set_log_file(log_file);
	}

	try {
		if(run_config().get_only_stats()){
			load_actor_interface_mapping();
			stats_test();
			return;
		}

		while(config_requirement()){
			log(LogLevel::WARNING, "Config needs to be reloaded for new actors software info");
		} //include req validation

		setup_test();
		const path out_path = _run_folder / "test_config.yaml";
		save_yaml(_config, out_path);
		run_test();
		stats_test();
		const path done_file = run_folder() / "done.txt";
		ofstream done_log(done_file, ios::out | ios::trunc);
		if(done_log.is_open()){
			done_log << "commit: " << git_commit_hash() << endl;
			done_log << "date:   " << current_time_string() << endl;
			done_log << "kernel: " << kernel_version() << endl;
			done_log.close();
		}
	} catch (const exception& e) {
		const path error_file = run_folder() / "errors.txt";
		ofstream error_log(error_file, ios::out | ios::app);
		if (error_log.is_open()) {
			error_log << "=== Error occurred at " << current_time_string() << " ===" << endl;
			error_log << "Exception type: " << typeid(e).name() << endl;
			error_log << "Message: " << e.what() << endl;

			if (const auto *te = dynamic_cast<const tester_error*>(&e)) {
				const auto &loc = te->where();
				error_log << "Location: " << loc.file_name()
						  << ":" << loc.line()
						  << " in " << loc.function_name() << endl;
			}

			error_log << endl;
			error_log.close();
			log(LogLevel::ERROR, "Error written to {}", error_file.string());
		} else {
			log(LogLevel::ERROR, "Failed to open error log file: {}", error_file.string());
		}
		log(LogLevel::INFO, "Cleaning up resources before exit...");
		clean();
	}
}

void RunStatus::get_or_create_connection(const ActorPtr &actor){
	if(actor->conn){ return; }
	shared_ptr<ExternalConn> conn;
	if(actor["external_OS"] == "openwrt"){
		conn = make_shared<OpenWrtConn>();
	} else{
		throw not_implemented_err("Not known external_OS: " + actor["external_OS"]);
	}

	if(!conn->connect(actor)){
		throw config_err("Failed to connect to external actor");
	}
	actor->conn = conn;
}

void RunStatus::run_test(){
	process_manager.write_log_all("@START");
	const auto module_name = config().at("attacker_module");

	if(const auto run_it = attack_module_maps::run_map.find(module_name); run_it != attack_module_maps::run_map.end()){
		run_it->second(*this);
	} else{ log(LogLevel::DEBUG, "run function not set for {}", module_name.get<string>()); }

	process_manager.write_log_all("@END");
	process_manager.stop_all();
}

void RunStatus::stats_test() const{
	const auto module_name = config().at("attacker_module");
	if(const auto run_it = attack_module_maps::stats_map.find(module_name); run_it != attack_module_maps::stats_map.end()){
		run_it->second(*this);
	} else{ log(LogLevel::DEBUG, "run function not set for {}",  module_name.get<string>()); }
}

void write_actors_csv(const ActorCMap &actors, ofstream &ofs){
	for(const auto &[name, actor]: actors){
		ofs << actor[SK::source].value_or("<none>") << ","
			<< name << "," << actor[SK::iface].value_or("<none>") << ","
			<< actor[SK::mac].value_or("<none>") << ","
			<< actor[SK::driver_name].value_or("<none>") << ","
			<< actor[SK::channel].value_or("<none>") << ",";
		// CSV-quote the JSON field: wrap in '"', escape inner '"' as '""'
		const string raw_json = actor->to_json().dump();
		ofs << '"';
		for(const char c : raw_json){ if(c == '"') ofs << '"'; ofs << c; }
		ofs << '"' << endl;
	}
}

unordered_map<string,string> RunStatus::scan_attack_configs(const CONFIG_TYPE ct){
	unordered_map<string,string> t_map;
	const path attack_config_dir = path(PROJECT_ROOT_DIR) / "attack_config";

	if(!exists(attack_config_dir) || !is_directory(attack_config_dir)){ return t_map; }

	for(const auto &entry: recursive_directory_iterator(attack_config_dir)){
		const auto &path = entry.path();
		string filename = path.filename().string();
		if(filename == "global_config.yaml" || filename.ends_with(".schema.yaml") || path.extension() != ".yaml" || path
			.string().find("/validator/") != string::npos || path.string().find("/target/") != string::npos){
			continue;
		}
		try{
			YAML::Node config = YAML::LoadFile(path.string());
			nlohmann::json config_json = yaml_to_json(config);
			if(!config_json.contains("name")){ throw config_err("Path " + path.string() + " has no valid name"); }
			auto name = config["name"].as<string>();
			if(config_json.contains("config_type") && config_json.at("config_type") == "test_suite" && ct ==
				TEST_SUITE){
				t_map[name] = path.string();
			} else if(ct == TEST && (!config_json.contains("config_type") || config_json.at("config_type") == "test")){
				if(t_map.contains(name)){
					throw config_err("Configs " + t_map[name] + " and " + path.string() + " have same name!");
				}
				t_map[name] = path.string();
			}
		} catch(const YAML::Exception &e){ throw config_err("Invalid yaml " + string(e.what())); }
	}
	return t_map;
}

ActorPtr &RunStatus::get_actor(const string &actor_name){
	if(const auto it = actors.find(actor_name); it != actors.end()){ return it->second; }
	throw config_err("Actor " + actor_name + " not found in actors map");
}

void RunStatus::print_test_list(){
	auto tests = scan_attack_configs(TEST);
	if(tests.empty()){
		cout << "In program are not any tests" << endl;
		return;
	}
	for(const auto &[name, path]: tests){
		cout << "Test: " << name << " -> " << path << endl;
	}
}

void RunStatus::start_observers(){
	for(const auto &observer: observers | views::values){
		observer->start(*this);
	}
}

string RunStatus::findConfigByTestName(const string &name){
	if(auto tests = scan_attack_configs(); tests.contains(name)){ return tests[name]; }
	throw config_err("Unknown test name: " + name);
}

void RunStatus::log_events(vector<unique_ptr<GraphElements>> &elements,
							// { actor_name, pattern, label, color }
							initializer_list<tuple<string,string,string,string>> event_d
) const{
	for(auto &[actor, pattern, label, color]: event_d){
		elements.push_back(make_unique<EventLines>(get_time_logs(*this, actor, pattern), label, color));
	}
}

void RunStatus::save_actor_interface_mapping() const{
	if(_run_folder.empty()){
		log(LogLevel::WARNING, "save_actor_interface_mapping: run_folder not set");
		return;
	}

	const string path = _run_folder / "mapping.csv";
	ofstream ofs(path, ios::out | ios::trunc);
	if(!ofs){
		log(LogLevel::ERROR, "Failed to open {} for writing CSV mapping", path);
		return;
	}

	ofs << "Type,ActorName,Interface,MAC,Driver,channel,json_obj" << endl;
	write_actors_csv(actors, ofs);

	ofs.close();
	log(LogLevel::INFO, "Actor/interface mapping written to CSV: {}", path);
}

void RunStatus::load_actor_interface_mapping(){
	const string csv_path = _run_folder / "mapping.csv";
	if(!exists(csv_path)){
		log(LogLevel::WARNING, "load_actor_interface_mapping: mapping.csv not found: {}", csv_path);
		return;
	}
	ifstream ifs(csv_path);
	if(!ifs){
		log(LogLevel::ERROR, "load_actor_interface_mapping: failed to open {}", csv_path);
		return;
	}

	string line;
	getline(ifs, line); // skip header: Type,ActorName,Interface,MAC,Driver,channel,json_obj

	while(getline(ifs, line)){ //FIXME wtf, parse json somehow.... better? (or change format)
		if(line.empty()) continue;
		// Format: source,actor_name,iface,mac,driver,channel,json_obj
		// json_obj may contain commas — split only on first 6 commas
		size_t name_start = string::npos, name_end = string::npos, json_start = string::npos;
		int commas = 0;
		for(size_t i = 0; i < line.size(); ++i){
			if(line[i] != ',') continue;
			++commas;
			if(commas == 1) name_start = i + 1;
			else if(commas == 2) name_end = i;
			else if(commas == 6){ json_start = i + 1; break; }
		}
		if(name_end == string::npos || json_start == string::npos){
			log(LogLevel::WARNING, "load_actor_interface_mapping: malformed row, skipping");
			continue;
		}
		const string actor_name = line.substr(name_start, name_end - name_start);
		string json_str = line.substr(json_start);
		// Strip CSV quoting and unescape '""' -> '"'
		if(json_str.size() >= 2 && json_str.front() == '"' && json_str.back() == '"'){
			json_str = json_str.substr(1, json_str.size() - 2);
			string unescaped;
			unescaped.reserve(json_str.size());
			for(size_t i = 0; i < json_str.size(); ++i){
				if(json_str[i] == '"' && i + 1 < json_str.size() && json_str[i + 1] == '"') ++i;
				unescaped += json_str[i];
			}
			json_str = std::move(unescaped);
		}
		const auto j = nlohmann::json::parse(json_str, nullptr, false);
		if(j.is_discarded()){
			log(LogLevel::WARNING, "load_actor_interface_mapping: invalid JSON for actor '{}'", actor_name);
			continue;
		}
		auto actor = make_shared<Actor_config>(j);
		actor->set(SK::actor_name, actor_name);
		actors.emplace(actor_name, ActorPtr(actor));
	}
	log(LogLevel::INFO, "Loaded {} actors from mapping.csv", actors.size());
}
}
