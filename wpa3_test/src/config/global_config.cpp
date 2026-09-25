#include "config/global_config.h"
#include "config/Run_Config.h"
#include "logger/error_log.h"
#include "setup/YAMLValidator.h"
#include "setup/config_parser.h"
#include "system/utils.h"
#include <filesystem>
#include <yaml-cpp/yaml.h>
#include "ex_program/hostapd/hostapd_helper.h"
#include "config/Actor_Config/actor_keys.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester{
using namespace std;
using namespace filesystem;
using json = nlohmann::json;

path global_config_path(const path &project_root_dir){
	return project_root_dir / "attack_config" / "global_config.yaml";
}

nlohmann::json &get_global_config(const path &project_root_dir, const bool reset){
	static json global_config_cache{};
	static bool loaded = false;

	if(!loaded || reset){
		try{
			const path global_config_file = global_config_path(project_root_dir);
			if(!exists(global_config_file)){
				throw config_err("Global paths configuration file not found: {}", global_config_file);
			}

			const YAML::Node yaml_node = YAML::LoadFile(global_config_file.string());
			global_config_cache = yaml_to_json(yaml_node);
			resolve_relative_paths(global_config_cache, global_config_file.parent_path());
			if(global_config_cache.contains("$validator")){
				const YAMLValidator validator(global_config_cache.at("$validator").get<string>());
				validator.validate(global_config_cache);
				global_config_cache.erase("$validator");
			}
			loaded = true;
		} catch(const YAML::Exception &e){
			throw config_err("Failed to parse global_config.yaml: {}", e.what());
		} catch(const exception &e){
			throw config_err("Failed to load global_config.yaml: ", e.what());
		}
	}
	return global_config_cache;
}

const Run_Config &get_global_run_config(const path &project_root_dir, const bool reset){
	static Run_Config run_config_cache{};
	static bool loaded = false;
	if(!loaded || reset){
		const json &cfg = get_global_config(project_root_dir, reset);
		run_config_cache = {};
		parse_run_config(cfg, run_config_cache);
		loaded = true;
	}
	return run_config_cache;
}

void disable_ifaces_NetworkManager(ActorMap actors){
	auto &gcfg = get_global_config();
	if(gcfg.at("actors").value("nm_exclude_actors", false)) {
		for(const auto &[name, actor]: actors) {
			if(!actor->get_or(SK::external_OS, "").empty()) continue;
			const string iface = actor->get_or(SK::iface, "");
			if(iface.empty()) continue;
			log(LogLevel::INFO, "Excluding {} ({}) from NetworkManager", iface, name);
			if(hw_capabilities::run_cmd({ "nmcli", "device", "set", iface, "managed", "no" }, nullopt, false) != 0)
				log(LogLevel::WARNING, "nmcli failed for {}, NetworkManager may interfere", iface);
		}
	}
}
void requirement_prebuild(nlohmann::json config) {
	const nlohmann::json &gcfg = get_global_config();
	// Pre-build external tools before config_requirement() moves interfaces to netns
	if(gcfg.value("compile_external", false)) {
		for(const auto &[_, actor_cfg]: config.at("actors").items()) {
			if(!actor_cfg.contains("setup")) continue;
			const auto &prog_cfg = actor_cfg.at("setup").value("program_config", nlohmann::json::object());
			if(prog_cfg.contains("openssl") && !prog_cfg.at("openssl").is_null())
				hostapd::get_openssl_paths(prog_cfg.at("openssl").get<string>());
		}
	}
}

}
