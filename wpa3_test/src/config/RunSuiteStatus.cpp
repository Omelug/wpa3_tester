#include "config/RunSuiteStatus.h"
#include "inteprrupt.h"
#include "system/utils.h"

#include <string>
#include <nlohmann/json.hpp>

#include <chrono>
#include <sstream>
#include <thread>

#include "default.h"
#include "config/global_config.h"
#include "config/RunStatus.h"
#include "config/Actor_Config/Actor_config.h"
#include "config/Actor_Config/Actor_Config_internal.h"
#include "logger/error_log.h"
#include "setup/config_parser.h"
#include "setup/requirement_validation.h"
#include "setup/YAMLValidator.h"
#include "suite/test_suites.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester{
using namespace std;
using namespace filesystem;
using namespace nlohmann;
using YNode = YAML::Node;

RunSuiteStatus::RunSuiteStatus(const path &config_path, string suite_name, const string &sub_folder){
	_config_path = config_path;
	if(!exists(config_path)){ throw config_err("Config not found: " + config_path.string()); }

	if(suite_name.empty()){
		const YNode node = YAML::LoadFile(config_path.string());
		if(!node["name"] || !node["name"].IsScalar())
			throw config_err("Config missing required string field 'name': " + config_path.string());
		suite_name = node["name"].as<string>();
	}
	string actual_sub_folder = ".";
	if(sub_folder.empty()){
		try{
			actual_sub_folder = relative_from("attack_config", config_path);
		}catch(const config_err &){
			log(LogLevel::ERROR, "relative_from issue");
		}
	}
	_run_folder = BASE_FOLDER / actual_sub_folder/ suite_name /LAST_RUN_DIR;
	log(LogLevel::INFO, "Used test suite config {}", _config_path.string());
	this->config = config_validation(_config_path);

	parse_run_config(config, run_config);
	run_config.merge_from(get_global_run_config());
	if(config.contains("wait_between_tests"))
		wait_between_tests = config.at("wait_between_tests").get<int>();
}

json RunSuiteStatus::config_validation(const path &config_path){
	try{
		const YNode config_node = YAML::LoadFile(config_path.string());
		json config_json = yaml_to_json(config_node);

		config_json = RunStatus::extends_recursive(config_json, config_path);
		RunStatus::validate_recursive(config_json, config_path.parent_path());

		//global validation
		const path global_schema_path = path(PROJECT_ROOT_DIR) / "attack_config" / "validator" /
				"test_suite_validator.schema.yaml";
		const YAMLValidator global_validator(global_schema_path.string());
		//global_validator.set_root_schema(yaml_to_json(YAML::LoadFile()));
		global_validator.validate(config_json);
		return config_json;
	} catch(const domain_error &){
		std::throw_with_nested(config_err("Schema error: " + config_path.string()));
	} catch(const invalid_argument &){
		std::throw_with_nested(config_err("Error in config: " + config_path.string()));
	} catch(const exception &){
		std::throw_with_nested(config_err("Config validation error: " + config_path.string()));
	}
}

void RunSuiteStatus::defined_by_path(basic_json<> source_j, const string &source_name, config_paths &test_map) const{
	const path rel_path = source_j.at("path").get<string>();
	path abs_path = absolute(_config_path.parent_path() / rel_path);
	test_map.emplace_back(source_name, "", abs_path);
}

void RunSuiteStatus::defined_by_name(basic_json<> source_j, const string &source_name, config_paths &test_map){
	const string name = source_j.at("test_name").get<string>();
	test_map.emplace_back(source_name, "", RunStatus::findConfigByTestName(name));
}

void replace_all(string &str, const string &from, const string &to){
	if(from.empty()) return;
	size_t start_pos = 0;
	while((start_pos = str.find(from, start_pos)) != string::npos){
		str.replace(start_pos, from.length(), to);
		start_pos += to.length();
	}
}

void RunSuiteStatus::defined_by_generator(basic_json<> source_info, const string &source_name,
										const path &test_config_folder, config_paths &test_map
){
	auto source_config = source_info.at("config");
	auto gen_folder = test_config_folder / source_name;

	error_code ec;
	create_public_dirs(gen_folder, ec);
	if(ec){ throw run_err("Unable to create generator directory"); }

	auto length = check_vars_len_same(source_info);
	auto vars = source_info.at("vars");

	for(size_t i = 0; i < length; ++i){
		auto tmp_path = path(gen_folder / (to_string(i) + ".tmp.yaml"));
		save_yaml(source_info.at("config"), tmp_path);

		ifstream ifs(tmp_path);
		if(!ifs.is_open()){ throw run_err("Could not open temp file for reading"); }
		string config_str((istreambuf_iterator(ifs)), istreambuf_iterator<char>());
		ifs.close();

		for(auto &[key, value]: vars.items()){
			const string json_placeholder = var_PREFIX + key;
			auto replacement = value[i].get<string>();
			replace_all(config_str, json_placeholder, replacement);
		}

		// unresolved var_
		if(config_str.find(var_PREFIX) != string::npos){
			remove(tmp_path);
			throw run_err("Unresolved " + var_PREFIX + " placeholders at index " + to_string(i));
		}

		const YNode saved_node = YAML::Load(config_str);
		const auto config_name = saved_node["name"].as<string>();

		auto test_config_path = gen_folder / (config_name + "_" + to_string(i) + ".yaml");
		remove(tmp_path);
		ofstream ofs(test_config_path);
		if(!ofs.is_open()){ throw run_err("Could not open final config file for writing"); }
		ofs << config_str;
		ofs.close();
		set_public_perms(test_config_path);

		RunStatus::config_validation(test_config_path);
		test_map.emplace_back(source_name, config_name, test_config_path);
	}
}

map<string,size_t> analyze_template_vars(const string &config_template){
	map<string,set<size_t>> found_indices;
	const regex var_regex(var_PREFIX + "([a-zA-Z0-9]+)_([0-9]+)");
	smatch match;

	// scan config for used vars
	auto search_start(config_template.cbegin());
	while(regex_search(search_start, config_template.cend(), match, var_regex)){
		found_indices[match[1]].insert(stoul(match[2]));
		search_start = match.suffix().first;
	}

	// 0... N , save count
	map<string,size_t> required_counts;
	for(auto &[name, indices]: found_indices){
		const size_t max_idx = *indices.rbegin();
		if(indices.size() != max_idx + 1){
			throw setup_err(
				"Variable '" + name + "' has gaps in indexing, expected sequence from 0 to " + to_string(max_idx));
		}
		required_counts[name] = indices.size();
	}

	return required_counts;
}

vector<pair<string,vector<vector<string>>>> prepare_variable_groups(const json &vars_node,
																	const map<string,size_t> &required_counts
){
	vector<pair<string,vector<vector<string>>>> groups;

	for(auto const &[name, count]: required_counts){
		if(!vars_node.contains(name)){
			throw run_err("Variable '" + name + "' missing in 'vars' definition.");
		}

		auto elements = vars_node.at(name).get<vector<string>>();
		if(count > elements.size()){
			throw run_err("Variable '" + name + "' needs " + to_string(count) + " values.");
		}

		// variations for one group
		ranges::sort(elements);
		vector<vector<string>> variations;

		do{
			// generate all permutations + deduplication
			vector current_var(elements.begin(), next(elements.begin(), static_cast<ptrdiff_t>(count)));
			if(ranges::find(variations, current_var) == variations.end()){
				variations.push_back(current_var);
			}
		} while(ranges::next_permutation(elements).found);

		groups.emplace_back(name, variations);
	}

	return groups;
}

// help config validation functions
size_t RunSuiteStatus::check_vars_len_same(basic_json<> source_info){
	// check len are same
	auto vars = source_info.at("vars");
	size_t length = 0;
	bool first = true;
	for(auto &[key, value]: vars.items()){
		if(first){
			length = value.size();
			first = false;
		} else if(value.size() != length){
			throw config_err("All vars lists must have the same length (error in '" + key + "')");
		}
	}
	return length;
}

void RunSuiteStatus::print_test_suite_list(){
	auto tests = RunStatus::scan_attack_configs(TEST_SUITE);
	if(tests.empty()){
		cout << "In program are not any test suites" << endl;
		return;
	}
	for(const auto &[name, path]: tests){ cout << "Test-suite: " << name << " -> " << path << endl; }
}

void RunSuiteStatus::print_tests_in_suite(const string &ts_name){
	RunSuiteStatus rss(findConfigByTestSuiteName(ts_name));
	auto tests = rss.get_test_paths();
	if(tests.empty()){
		cout << "Not tests in this suite" << endl;
		return;
	}
	for(const auto &[src, name, cfg_path]: tests){ cout << "Test: " << src << "/" << name << " -> " << cfg_path << endl; }
}

void RunSuiteStatus::generate_test_files(basic_json<> source_info,
										const vector<pair<string,vector<vector<string>>>> &groups,
										const path &gen_folder,
										const string &source_name, config_paths &test_map
){
	path tmp_template = gen_folder / "template_base.tmp.yaml";
	save_yaml(source_info.at("config"), tmp_template);

	ifstream ifs(tmp_template);
	if(!ifs.is_open()){ throw run_err("Could not open template file for reading"); }
	string raw_yaml_template((istreambuf_iterator(ifs)), istreambuf_iterator<char>());
	ifs.close();

	vector<size_t> indices(groups.size(), 0);
	bool done = false;
	size_t test_counter = 0;

	while(!done){
		string current_config_str = raw_yaml_template;
		for(size_t g = 0; g < groups.size(); ++g){
			const string &var_name = groups[g].first;
			const vector<string> &current_variation = groups[g].second[indices[g]];

			for(size_t i = 0; i < current_variation.size(); ++i){
				string placeholder = var_PREFIX + var_name + "_" + to_string(i);
				replace_all(current_config_str, placeholder, current_variation[i]);
			}
		}

		if(current_config_str.find(var_PREFIX) != string::npos){
			throw run_err("Unresolved " + var_PREFIX + " placeholders in test " + to_string(test_counter));
		}

		const YNode saved_node = YAML::Load(current_config_str);
		const auto config_name = saved_node["name"].as<string>();
		path test_path = gen_folder / (config_name + "_" + to_string(test_counter) + ".yaml");

		// save result to file
		ofstream ofs(test_path);
		if(!ofs.is_open()){ throw run_err("Could not open final config file for writing"); }
		ofs << current_config_str;
		ofs.close();
		set_public_perms(test_path);

		// result test config validation
		RunStatus::config_validation(test_path);
		test_map.emplace_back(source_name, config_name, test_path);

		// another index or stop
		test_counter++;
		for(size_t i = groups.size(); i-- > 0;){
			if(++indices[i] < groups[i].second.size()) break;
			if(i == 0){
				done = true;
			} else{
				indices[i] = 0;
			}
		}
	}
	remove(tmp_template);
}

void RunSuiteStatus::defined_by_permutation(basic_json<> source_info, const string &source_name,
											const path &test_config_folder, config_paths &test_map
){
	const auto gen_folder = test_config_folder / source_name;
	create_public_dirs(gen_folder);

	const auto vars_node = source_info.at("vars");
	const string config_template = source_info.at("config").dump();

	const auto required_counts = analyze_template_vars(config_template);

	// vector of (var_name, vector of var variations)
	const auto groups = prepare_variable_groups(vars_node, required_counts);
	generate_test_files(source_info, groups, gen_folder, source_name, test_map);
}

void RunSuiteStatus::defined_by_actor_filler(basic_json<> source_info, const string &source_name,
											const path &test_config_folder, config_paths &test_map
){

	cleanup_all_namespaces();
	const path rel = source_info.at("config").get<string>();
	path src = absolute(_config_path.parent_path() / rel);
	if(!exists(src)) throw config_err("actor_filler: config not found: " + src.string());

	const json template_config = RunStatus::config_validation(src);

	// get only internal actors
	ActorCMap rules;
	for(const auto &[actor_name, actor_j] : template_config.at("actors").items()){
		if(!actor_j.contains("source") || actor_j.at("source").get<string>() != "internal") continue;
		rules.emplace(actor_name, ActorPtr(make_shared<Actor_Config_internal>(actor_j)));
	}
	if(rules.empty()) throw config_err("actor_filler: no internal actors in " + src.string());

	if(!_hw_option_cache.internal_opts.has_value())
		_hw_option_cache.internal_opts = RunStatus::internal_options();

	const auto solutions = hw_capabilities::check_all_req_options(rules, *_hw_option_cache.internal_opts);
	if(solutions.empty()){

		Actor_config::print_ActorCMap("Actor rules", rules);
		Actor_config::print_ActorCMap("Actor options", *_hw_option_cache.internal_opts);
		throw req_err("actor_filler: no valid hardware assignments found, " + hw_capabilities::get_heuristic_err_msg(rules, *_hw_option_cache.internal_opts));
	}

	const path gen_folder = test_config_folder / source_name;
	error_code ec;
	create_public_dirs(gen_folder, ec);
	if(ec) throw run_err("actor_filler: unable to create directory");

	const string base_name = template_config.at("name").get<string>();
	for(const auto & solution : solutions){
		json cfg = template_config;

		// build stable hash from sorted actor_name=perm_mac pairs
		vector<string> mac_parts;
		for(const auto &[actor_name, hw] : solution){
			const auto &perm_mac = (*hw)[SK::permanent_mac];
			if(!perm_mac.has_value()) continue;
			mac_parts.push_back(actor_name + "=" + *perm_mac);
			cfg["actors"][actor_name]["selection"]["permanent_mac"] = *perm_mac;
		}
		ranges::sort(mac_parts);
		string mac_concat;
		for(const auto &p : mac_parts) mac_concat += p;
		ostringstream oss;
		oss << hex << hash<string>{}(mac_concat);
		const string hash_str = oss.str().substr(0, 8);

		cfg["name"] = base_name + "_" + hash_str;

		const path test_path = gen_folder / (hash_str + "_actor_filler.yaml");
		save_yaml(cfg, test_path);
		set_public_perms(test_path);
		RunStatus::config_validation(test_path);
		test_map.emplace_back(source_name, cfg.at("name").get<string>(), test_path);
	}
}

config_paths RunSuiteStatus::get_test_paths(){
	const auto test_config_folder = _run_folder /TEST_SUITE_CONFIG_DIR;
	config_paths test_map;
	for(auto &[source_name, source_info]: config.at("tests").items()){
		if(source_info.contains("path")){
			defined_by_path(source_info, source_name, test_map);
			continue;
		}
		if(source_info.contains("test_name")){
			defined_by_name(source_info, source_name, test_map);
			continue;
		}

		const string &type = source_info.at("type");

		error_code ec;
		create_public_dirs(test_config_folder, ec);
		if(ec){ throw run_err("Unable to create directory"); }

		if(type == "generator"){
			defined_by_generator(source_info, source_name, test_config_folder, test_map);
			continue;
		}
		if(type == "permutation"){
			defined_by_permutation(source_info, source_name, test_config_folder, test_map);
			continue;
		}
		if(type == "actor_filler"){
			defined_by_actor_filler(source_info, source_name, test_config_folder, test_map);
			continue;
		}
		throw config_err("invalid source type");
	}

	return test_map;
}

void RunSuiteStatus::execute(){
	HwOptionCache hw_cache;
	auto tests_paths = get_test_paths();

	if(config.contains("suite_functions")){
		const string module_name = config.at("suite_functions").get<string>();
		if(const auto it = suite::test_suite_setup_map.find(module_name); it != suite::test_suite_setup_map.end()){
			it->second(*this);
		} else{
			log(LogLevel::WARNING, "suite_functions '{}' not found in test_suite_setup_map", module_name);
		}
	}

	for(size_t i = 0; i < tests_paths.size(); ++i){
		if(g_interrupted.load()){
			log(LogLevel::WARNING, "Suite interrupted by Ctrl+C, stopped after {} of {} tests", i, tests_paths.size());
			break;
		}
		const auto &[src_key, name, test_path] = tests_paths[i];
		RunStatus rs(test_path, name, ".");
		rs.hw_option_cache(hw_cache);
		rs.run_config(run_config);
		path test_name = rs.config().at("name").get<string>();
		const path test_folder = run_folder() / src_key / test_name;
		if(exists(test_folder)) set_public_perms(test_folder);
		rs.run_folder(test_folder);
		rs.execute();
		hw_cache = rs.hw_option_cache();
		if(wait_between_tests > 0 && i + 1 < tests_paths.size()){
			for(int j = 0; j < wait_between_tests * 10 && !g_interrupted.load(); ++j)
				this_thread::sleep_for(chrono::milliseconds(100));
		}
	}

	if(config.contains("suite_functions")){
		const string module_name = config.at("suite_functions").get<string>();
		if(const auto it = suite::test_suite_report_map.find(module_name); it != suite::test_suite_report_map.end()){
			it->second(*this);
		} else{
			log(LogLevel::WARNING, "suite_functions '{}' not found in test_suite_report_map", module_name);
		}
	}
}

void RunSuiteStatus::execute(const string &test_name){
	auto tests_paths = get_test_paths();
	const auto it = ranges::find_if(tests_paths, [&](const auto &p){ return get<1>(p) == test_name; });
	if(it == tests_paths.end()){
		log(LogLevel::WARNING, "Test '{}' not found — run the full suite first to generate test configs", test_name);
		for(const auto &[src, name, cfg_path]: tests_paths)
			log(LogLevel::WARNING, "  available: {}/{}", src, name);
		throw config_err("Test '" + test_name + "' not found in suite");
	}

	const auto &[src_key, name, test_path] = *it;
	RunStatus rs(test_path, name, ".");
	rs.run_config(run_config);
	rs.run_config(get_global_run_config());
	rs.run_folder(run_folder() / src_key / rs.config().at("name").get<string>());
	rs.execute();
}

string RunSuiteStatus::findConfigByTestSuiteName(const string &name){
	auto tests = RunStatus::scan_attack_configs(TEST_SUITE);
	if(tests.contains(name)){ return tests[name]; }
	throw config_err("Unknown test suite name: " + name);
}
}