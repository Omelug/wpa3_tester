#include <fstream>
#include <nlohmann/json.hpp>
#include <yaml-cpp/yaml.h>
#include "config/RunStatus.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "setup/YAMLValidator.h"
#include "system/utils.h"
#include "system/firmware/ath9k_htc.h"

namespace wpa3_tester{
using namespace std;
using json = nlohmann::json;
using YNode = YAML::Node;
using namespace filesystem;

json yaml_to_json(const YNode &node){
	if(node.IsScalar()){
		if(node.Tag() == "!"){
			return node.as<string>();
		}
		try{ return node.as<bool>(); } catch(...){}
		try{ return node.as<int64_t>(); } catch(...){}
		try{ return node.as<double>(); } catch(...){}
		return node.as<string>();
	}
	if(node.IsSequence()){
		auto j = json::array();
		for(auto const &item: node) j.push_back(yaml_to_json(item));
		return j;
	}
	if(node.IsMap()){
		auto j = json::object();
		for(auto it = node.begin(); it != node.end(); ++it){
			j[it->first.as<string>()] = yaml_to_json(it->second);
		}
		return j;
	}
	return {};
}

void deep_merge(json &base, const json &patch){
	for(auto it = patch.begin(); it != patch.end(); ++it){
		if(it.key() == "$DELETE"){
			if(it.value().is_string()) base.erase(it.value().get<string>());
			else if(it.value().is_array())
				for(const auto &k: it.value()) if(k.is_string()) base.erase(k.get<string>());
		} else if(it.value().is_object() && base.contains(it.key()) && base[it.key()].is_object()){
			deep_merge(base[it.key()], it.value());
		} else{
			base[it.key()] = it.value();
		}
	}
}

json resolve_extends(json current_node, const path &base_dir, vector<string> &hierarchy, const bool is_child = false){
	if(!current_node.is_object()){
		return current_node;
	}

	// resolve $validator paths to be absolute (string or list)
	if(current_node.contains("$validator")){
		if(current_node["$validator"].is_string()){
			current_node["$validator"] = absolute(base_dir / current_node["$validator"].get<string>()).string();
		} else if(current_node["$validator"].is_array()){
			for(auto &v: current_node["$validator"]){
				if(v.is_string()) v = absolute(base_dir / v.get<string>()).string();
			}
		}
	}

	if(!current_node.contains("$extends")){
		for(auto &[key, value]: current_node.items()){
			value = resolve_extends(value, base_dir, hierarchy, true);
		}
		// Only strip $DELETE at file-root level (is_child=false).
		// Nested $DELETE must survive so deep_merge can act on it when
		// the enclosing file's $extends is processed.
		if(!is_child) current_node.erase("$DELETE");
		return current_node;
	}

	// normalize $extends to a list
	json extends_list;
	if(current_node["$extends"].is_string()){
		extends_list = json::array({current_node["$extends"]});
	} else if(current_node["$extends"].is_array()){
		extends_list = current_node["$extends"];
	} else{
		throw config_err("'$extends' must be a string or list of strings");
	}
	current_node.erase("$extends");

	// resolve current node's own children relative to its base_dir first
	for(auto &[key, value]: current_node.items()){
		value = resolve_extends(value, base_dir, hierarchy, true);
	}

	// merge all parents in order (later entries override earlier)
	json merged = json::object();
	for(const auto &ext_item: extends_list){
		const path parent_path = absolute(base_dir / ext_item.get<string>());
		const string parent_path_str = parent_path.string();

		if(ranges::find(hierarchy, parent_path_str) != hierarchy.end()){
			throw config_err("Circular inheritance detected! File already in hierarchy: " + parent_path_str);
		}

		hierarchy.push_back(parent_path_str);
		json parent_json = yaml_to_json(YAML::LoadFile(parent_path.string()));
		parent_json = resolve_extends(parent_json, parent_path.parent_path(), hierarchy);
		deep_merge(merged, parent_json);
		hierarchy.pop_back();
	}

	// apply root-level $DELETE: remove keys from merged before current overrides
	if(current_node.contains("$DELETE")){
		const json del = current_node["$DELETE"];
		current_node.erase("$DELETE");
		if(del.is_string()) merged.erase(del.get<string>());
		else if(del.is_array())
			for(const auto &k: del) if(k.is_string()) merged.erase(k.get<string>());
	}

	// current node overrides all parents (nested $DELETE in sub-objects handled by deep_merge)
	deep_merge(merged, current_node);
	return merged;
}

json RunStatus::extends_recursive(const nlohmann::json &config_json, const path &config_path){
	const path config_dir = config_path.parent_path();
	vector<string> hierarchy;
	// prevent self-extension: include the current config file in the hierarchy
	hierarchy.push_back(absolute(config_path).string());
	return resolve_extends(config_json, config_dir, hierarchy);
}

void RunStatus::validate_recursive(nlohmann::json &current_node, const path &base_dir){
	if(current_node.is_object()){
		if(current_node.contains("$validator")){
			auto apply_validator = [&](const string &schema_file){
				const YAMLValidator validator(base_dir / schema_file);
				validator.validate(current_node);
			};
			if(current_node.at("$validator").is_string()){
				apply_validator(current_node.at("$validator").get<string>());
			} else if(current_node.at("$validator").is_array()){
				// copy before the loop: validate() reassigns current_node, which invalidates iterators into it
				const json validator_list = current_node.at("$validator");
				for(const auto &v: validator_list){
					if(v.is_string()) apply_validator(v.get<string>());
				}
			}
			current_node.erase("$validator");
		}

		for(auto &[key, value]: current_node.items()){
			validate_recursive(value, base_dir);
		}
	} else if(current_node.is_array()){
		for(auto &element: current_node){
			validate_recursive(element, base_dir);
		}
	}
}

json RunStatus::config_validation(const path &config_path){
	try{
		const YNode config_node = YAML::LoadFile(config_path);
		json config_json = yaml_to_json(config_node);

		// extends, validators
		config_json = extends_recursive(config_json, config_path);
		validate_recursive(config_json, config_path.parent_path());

		//global validation
		const path global_schema_path = path(PROJECT_ROOT_DIR) / "attack_config" / "validator" /
				"test_validator.schema.yaml";
		const YAMLValidator validator(global_schema_path);
		validator.validate(config_json);
		return config_json;
	} catch(const domain_error &e){
		throw config_err(string("Schema error: ") + e.what());
	} catch(const invalid_argument &e){
		throw config_err(string("Error in config: ") + e.what());
	} catch(const exception &e){
		throw config_err(string("Config validation error: ") + e.what());
	}
}

void RunStatus::ensure_requirement(const string &req) const{
	assert(req == "ath_masker" or req == "ath9k_noorder_change");
	if(req == "ath_masker") firmware::load_ath_masker(_run_config.get_install_req());
	if(req == "ath9k_noorder_change") firmware::load_ath9k_noorder_change();
}

void RunStatus::check_local_requirements(){
	set<string> all_requirements;

	if(_config.contains("requirements")){
		const auto &reqs = _config.at("requirements");
		if(reqs.is_object() && reqs.contains("simple")){
			for(const auto &req: reqs.at("simple")){
				if(req.is_string()) all_requirements.insert(req.get<string>());
			}
		}
	}

	// Per-actor requirements
	for(auto &[actor_name, actor_data]: _config.at("actors").items()){
		if(!actor_data.contains("setup") || !actor_data.at("setup").contains("requirements")) continue;
		const auto &reqs = actor_data.at("setup").at("requirements");
		if(reqs.is_object() && reqs.contains("simple")){
			for(const auto &req: reqs.at("simple")) if(req.is_string()) all_requirements.insert(req.get<string>());
		}
	}

	for(const auto &req: all_requirements){
		log(LogLevel::WARNING, "Found requirement: {}", req);
		ensure_requirement(req);
	}
}

void save_yaml(const json &json_obj, const path &out_path){
	const YAML::Node node = YAML::Load(json_obj.dump());
	auto force_block_style = [](auto &self, YAML::Node yaml_node) ->void{
		if(yaml_node.IsMap() || yaml_node.IsSequence()){
			yaml_node.SetStyle(YAML::EmitterStyle::Block);
			for(auto it = yaml_node.begin(); it != yaml_node.end(); ++it){
				if(yaml_node.IsMap()){
					self(self, it->second);
				} else{
					self(self, *it);
				}
			}
		}
	};
	force_block_style(force_block_style, node);
	ofstream out(out_path);
	if(!out) throw run_err("Failed to open {} for writing", out_path);
	out << node << endl;
	out.close();
	set_public_perms(out_path);
	log(LogLevel::DEBUG, "Config saved to {}", out_path);
}
}