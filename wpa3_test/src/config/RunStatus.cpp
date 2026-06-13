#include "config/RunStatus.h"
#include <filesystem>
#include <optional>
#include <string>
#include <yaml-cpp/yaml.h>
#include "inteprrupt.h"
#include "attacks/attacks.h"
#include "config/global_config.h"
#include "config/Observer_config.h"
#include "ex_program/external_actors/openwrt/OpenWrtConn.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "setup/config_parser.h"
#include "system/hw_capabilities.h"
#include "system/utils.h"

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
	_run_folder = BASE_FOLDER / actual_sub_folder / testName / "last_run";
	log(LogLevel::INFO, "Used config {}", config_path);
	_config = config_validation(_config_path);

	parse_run_config(_config, _run_config);
	_run_config.merge_from(get_global_run_config());
}

void RunStatus::clean(){
	process_manager.stop_all();
	actors.clear();
	observers.clear();
}

void RunStatus::execute(){
	globalRunStatus = this;

	if(exists(_run_folder)){
		if(access(_run_folder.string().c_str(), W_OK) != 0){
			log(LogLevel::WARNING, "Run folder not writable (created by different user?), removing: {}", absolute(_run_folder));
			error_code ec;
			remove_all(_run_folder, ec);
			if(ec) throw run_err("Run folder not writable and cannot remove: {}:{}", _run_folder, ec.message());
		} else {
			if(_run_config.get_rewrite() == RewriteMode::none && (exists(_run_folder / "errors.txt") || exists(_run_folder / "done.txt"))){
				log(LogLevel::DEBUG, "Skipping: {}", absolute(_run_folder));
				return;
			}
			if(_run_config.get_rewrite() == RewriteMode::errors && !(exists(_run_folder / "errors.txt") || !exists(_run_folder / "done.txt"))){
				log(LogLevel::WARNING, "Skipping already successfully run test : {}", absolute(_run_folder));
				return;
			}
			if(_run_config.get_delete_old()){
				log(LogLevel::DEBUG, "Deleting old run folder: {}", absolute(_run_folder));
				remove_all(_run_folder);
			}
		}
	}

	// Ensure parent directories exist
	error_code ec;
	create_public_dirs(_run_folder, ec);
	if(ec) throw run_err("Unable to create run base directory");

	// Initialize log file if save_log is enabled
	if(_run_config.get_save_log()){
		const path log_file = _run_folder / "logger" / "tester.log";
		set_log_file(log_file);
	}
	struct LogGuard { ~LogGuard(){ close_log_file(); } } log_guard;

	try {
		try {
			auto &gcfg = get_global_config();
			if(gcfg.contains("regulatory_domain")){
				const string reg = gcfg.at("regulatory_domain").get<string>();
				log(LogLevel::INFO, "Setting regulatory domain: iw reg set {}", reg);
				if(hw_capabilities::run_cmd({"iw", "reg", "set", reg}, nullopt, false) != 0)
					log(LogLevel::WARNING, "Failed to set regulatory domain {}, NO_IR restrictions may apply", reg);
			}
		} catch(const exception &e){
			log(LogLevel::DEBUG, "Regulatory domain not applied: {}", e.what());
		}

		if(run_config().get_only_stats()){
			load_actor_interface_mapping();
			stats_test();
			return;
		}

		while(config_requirement()){
			log(LogLevel::WARNING, "Config needs to be reloaded for new actors software info");
		} //include req validation

		try {
			auto &gcfg = get_global_config();
			if(gcfg.value("nm_exclude_actors", false)){
				for(const auto &[name, actor]: actors){
					if(!actor->get_or(SK::external_OS, "").empty()) continue;
					const string iface = actor->get_or(SK::iface, "");
					if(iface.empty()) continue;
					log(LogLevel::INFO, "Excluding {} ({}) from NetworkManager", iface, name);
					if(hw_capabilities::run_cmd({"nmcli", "device", "set", iface, "managed", "no"}, nullopt, false) != 0)
						log(LogLevel::WARNING, "nmcli failed for {}, NetworkManager may interfere", iface);
				}
			}
		} catch(const exception &e){
			log(LogLevel::DEBUG, "nm_exclude_actors not applied: {}", e.what());
		}

		setup_test();
		if(g_interrupted.load()){
			log(LogLevel::WARNING, "Test stopped by Ctrl+C");
			clean();
			return;
		}
		const path out_path = _run_folder / "test_config.yaml";
		save_yaml(_config, out_path);
		run_test();
		if(g_interrupted.load()){
			log(LogLevel::WARNING, "Test stopped by Ctrl+C");
			return;
		}
		stats_test();
		const path done_file = run_folder() / "done.txt";
		ofstream done_log(done_file, ios::out | ios::trunc);
		if(done_log.is_open()){
			done_log << "commit: " << git_commit_hash() << endl;
			done_log << "date:   " << current_time_string() << endl;
			done_log << "kernel: " << kernel_version() << endl;
			done_log.close();
			set_public_perms(done_file);
		}
	} catch (const exception& e) {
		if(g_interrupted.load()) log(LogLevel::WARNING, "Test stopped by Ctrl+C");

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
			set_public_perms(error_file);
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
	if(actor.get(SK::external_OS) == "openwrt"){
		conn = make_shared<OpenWrtConn>();
	} else{
		throw not_implemented_err("Not known external_OS: " + actor.get(SK::external_OS));
	}

	if(!conn->connect(actor)){
		throw config_err("Failed to connect to external actor");
	}
	actor->conn = conn;
}

void RunStatus::run_test(){
	process_manager.write_log_all(START_tag);
	const auto module_name = config().at("attacker_module");

	if(const auto run_it = attack_module_maps::run_map.find(module_name); run_it != attack_module_maps::run_map.end()){
		run_it->second(*this);
	} else{ log(LogLevel::DEBUG, "run function not set for {}", module_name.get<string>()); }

	process_manager.write_log_all(END_tag);
	process_manager.stop_all();
}

void RunStatus::stats_test() const{
	const auto module_name = config().at("attacker_module");
	if(const auto run_it = attack_module_maps::stats_map.find(module_name); run_it != attack_module_maps::stats_map.end()){
		run_it->second(*this);
	} else{ log(LogLevel::DEBUG, "stats function not set for {}",  module_name.get<string>()); }
}

void write_actors_csv(const ActorCMap &actors, ofstream &ofs){
	for(const auto &[name, actor]: actors){
		ofs << actor->get_or(SK::source, "<none>") << ","
			<< name << "," << actor->get_or(SK::iface, "<none>") << ","
			<< actor->get_or(SK::mac, "<none>") << ","
			<< actor->get_or(SK::driver_name, "<none>") << ","
			<< actor->get_or(SK::channel, "<none>") << ",";
		// CSV-quote the JSON field
		const string raw_json = actor->to_json().dump();
		ofs << '"';
		for(const char c : raw_json){ if(c == '"') ofs << '"'; ofs << c; }
		ofs << '"' << endl;
	}
}

bool RunStatus::should_skip(const path &p){
	if(p.string().ends_with(".schema.yaml")) return true;
	// components
	if(p.string().ends_with(".comp.yaml")) return true; //TODO add to documentation
	const auto rel = relative(p, ATTACK_CONFIG);
	const auto first = *rel.begin();
	if(first == "validator") return true;
	if(first == "target")    return true;
	if(rel == "global_config.yaml") return true;
	if(p.extension() != ".yaml") return true;
	if(rel.string().find("/validator/") != string::npos) return true;
	if(rel.string().find("/target/") != string::npos) return true;
	return false;
}

unordered_map<string,string> RunStatus::scan_attack_configs(const CONFIG_TYPE ct){
	unordered_map<string,string> t_map;
	const path attack_config_dir = path(PROJECT_ROOT_DIR) / "attack_config";

	if(!exists(attack_config_dir) || !is_directory(attack_config_dir)){ return t_map; }

	for(const auto &entry: recursive_directory_iterator(attack_config_dir)){
		const auto &path = entry.path();
		string filename = path.filename().string();
		if(should_skip(entry.path())) continue;
		try{
			YAML::Node config = YAML::LoadFile(path.string());
			nlohmann::json config_json = yaml_to_json(config);
			if(!config_json.contains("name")){ throw config_err("Path {} has no valid name", path); }
			auto name = config["name"].as<string>();
			if(config_json.contains("config_type") && config_json.at("config_type") == "test_suite" && ct ==
				TEST_SUITE){
				t_map[name] = path.string();
			} else if(ct == TEST && (!config_json.contains("config_type") || config_json.at("config_type") == "test")){
				if(t_map.contains(name)){
					throw config_err("Configs {} and {} have same name!", t_map[name], path);
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
	throw config_err("Unknown test name: " + name + "Isn't it test suite?");
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
	set_public_perms(path);
	log(LogLevel::INFO, "Actor/interface mapping written to CSV: {}", path);
}

void RunStatus::load_actor_interface_mapping(){
	const string csv_path = _run_folder / "mapping.csv";
	ifstream ifs(csv_path);
	if(!ifs){
		log(LogLevel::WARNING, "load_actor_interface_mapping: mapping.csv not found: {}", csv_path);
		return;
	}

	string line;
	getline(ifs, line); // skip header: source,actor_name,iface,mac,driver,channel,json_obj

	while(getline(ifs, line)){
		if(line.empty()) continue;

		// json_obj (field 7) may contain commas — locate only the first 6
		auto npos = string::npos;
		auto next = [&](const size_t from){ return line.find(',', from); };
		size_t c1 = next(0);
		size_t c2 = c1 != npos ? next(c1 + 1) : npos;
		size_t c6 = c2;
		for(int i = 0; i < 4 && c6 != npos; ++i) c6 = next(c6 + 1);

		if(c2 == npos || c6 == npos){
			log(LogLevel::WARNING, "load_actor_interface_mapping: malformed row, skipping");
			continue;
		}

		const string actor_name = line.substr(c1 + 1, c2 - c1 - 1);
		string json_str = line.substr(c6 + 1);

		// Strip CSV quoting and unescape "" -> "
		if(json_str.size() >= 2 && json_str.front() == '"' && json_str.back() == '"'){
			json_str = json_str.substr(1, json_str.size() - 2);
			for(size_t i = 0; i + 1 < json_str.size(); ++i)
				if(json_str[i] == '"' && json_str[i + 1] == '"')
					json_str.erase(i + 1, 1);
		}

		const auto j = nlohmann::json::parse(json_str, nullptr, false);
		if(j.is_discarded()){
			log(LogLevel::WARNING, "load_actor_interface_mapping: invalid JSON for actor '{}'", actor_name);
			continue;
		}
		auto actor = Actor_config::create(j);
		actor->set(SK::actor_name, actor_name);
		actors.emplace(actor_name, ActorPtr(actor));
	}
	log(LogLevel::INFO, "Loaded {} actors from mapping.csv", actors.size());
}

void RunStatus::save_result(const nlohmann::json& j) const{
	const path p = run_folder() / "result.json";
	ofstream f(p);
	if(!f.is_open()){ log(LogLevel::ERROR, "Cannot write result.json"); return; }
	f << j.dump(2) << "\n";
	f.close();
	set_public_perms(p);
}

nlohmann::json RunStatus::load_result() const{
	const path p = run_folder() / "result.json";
	ifstream f(p);
	if(!f.is_open()){
		throw stats_err("result.json not found");
	}
	return  nlohmann::json::parse(f);
}

}
