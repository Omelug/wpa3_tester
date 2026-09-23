#include <chrono>
#include <csignal>
#include <filesystem>
#include <sstream>
#include <sys/stat.h>
#include <sys/wait.h>
#include "attacks/two_iface/TwoIfaceActive.h"
#include "attacks/two_iface/TwoIfaceInject.h"
#include "config/Actor_Config/Actor_config.h"
#include "config/Observer_config.h"
#include "config/RunStatus.h"
#include "config/global_config.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "interrupt.h"
#include "logger/error_log.h"
#include "logger/log_util.h"
#include "setup/config_parser.h"
#include "setup/usb_helper.h"
#include "system/firmware/ath9k_htc.h"
#include "system/hw_capabilities.h"
#include "system/netlink_helper.h"
#include "visual/suite_helper.h"
#include "wizard/rssi_condition.h"

using namespace std;
using namespace filesystem;
using nlohmann::json;

namespace wpa3_tester {
using namespace observer;

void RunStatus::parse_requirements() {
	for(const auto &[actor_name, actor]: _config.at("actors").items()) {
		auto [it, inserted] = actors.emplace(actor_name, ActorPtr(Actor_config::create(actor)));
		it->second->set(SK::actor_name, actor_name);
	}
	if(!_config.contains("observers")) return;
	for(const auto &[observer_name, observer]: _config.at("observers").items()) {
		auto [it, inserted] = observers.emplace(observer_name, ObserverPtr(make_shared<Observer_config>(observer)));
		it->second->observer_name = observer_name;
	}
}

static vector<pid_t> pids_in_ns(const string &ns_name) {
	const string ns_path = "/var/run/netns/" + ns_name;

	struct stat ns_stat{};
	if(stat(ns_path.c_str(), &ns_stat) != 0) return {};
	const ino_t target_inode = ns_stat.st_ino;

	vector<pid_t> result;
	for(const auto &entry: directory_iterator("/proc")) {
		const string filename = entry.path().filename().string();
		// only numeric entries (PIDs)
		if(filename.find_first_not_of("0123456789") != string::npos) continue;

		const string net_ns_link = entry.path().string() + "/ns/net";
		struct stat link_stat{};
		if(stat(net_ns_link.c_str(), &link_stat) != 0) continue;
		if(link_stat.st_ino == target_inode) { result.push_back(stoi(filename)); }
	}
	return result;
}

void kill_process_in_ns_name(const string &ns_name) {
	const vector<pid_t> pids = pids_in_ns(ns_name);
	if(pids.empty()) return;

	for(const pid_t p: pids) kill(p, SIGTERM);

	const auto deadline = chrono::steady_clock::now() + chrono::milliseconds(500);

	// Wait for all pids together under one shared deadline
	bool all_dead = false;
	while(!all_dead && chrono::steady_clock::now() < deadline) {
		all_dead = true;
		for(const pid_t p: pids) {
			if(exists("/proc/" + to_string(static_cast<long>(p)))) all_dead = false;
		}
		if(!all_dead) interruptible_sleep(chrono::milliseconds(10));
	}

	// SIGKILL survivors
	for(const pid_t p: pids) {
		if(exists("/proc/" + to_string(static_cast<long>(p)))) {
			kill(p, SIGKILL);
			log(LogLevel::DEBUG, "SIGKILL process {} from namespace {}", p, ns_name);
		}
	}

	for(const pid_t p: pids) {
		waitpid(p, nullptr, 0);
		log(LogLevel::DEBUG, "Killed process {} from namespace {}", p, ns_name);
	}
}

static vector<string> psy_if_in_ns(const string &ns_name) {
	const string out = hw_capabilities::run_cmd_output({ "iw", "dev" }, ns_name);

	vector<string> result;
	istringstream ss(out);
	string token;
	while(ss >> token) {
		if(token == "Interface") {
			string iface;
			if(ss >> iface) {
				result.push_back(iface);
				log(LogLevel::DEBUG, "iface in ns {}:{}", ns_name, iface);
			}
		}
	}
	return result;
}

void cleanup_all_namespaces() {
	log(LogLevel::INFO, "Cleanup all namespaces...");

	const path netns_dir = "/var/run/netns";
	if(!exists(netns_dir)) {
		log(LogLevel::INFO, "Cleanup complete.");
		return;
	}

	for(const auto &entry: directory_iterator(netns_dir)) {
		const auto ns_name = entry.path().filename().string();
		log(LogLevel::INFO, "Cleaning up processes in namespace: {}", ns_name);
		kill_process_in_ns_name(ns_name);

		const auto ifaces = psy_if_in_ns(ns_name);
		netlink_helper::delete_ns_and_wait(ns_name, ifaces);
	}
	log(LogLevel::INFO, "Cleanup complete.");
}

ActorCMap get_actors(const ActorCMap &actors, const string &source) {
	unordered_map<string, ActorPtr> result;
	for(auto &[name, cfg]: actors) {
		auto it = cfg[SK::source];
		if(cfg[SK::source].has_value() && cfg[SK::source].value() == source) { result.emplace(name, cfg); }
	}
	return result;
}

bool RunStatus::config_requirement() {
	hw_capabilities::run_cmd({ "rfkill", "unblock", "all" }, nullopt, false);
	hw_capabilities::run_cmd({ "modprobe", "-r", "mac80211_hwsim" }, nullopt, false);
	firmware::disable_custom_drivers();
	check_local_requirements();

	for(const auto &iface: hw_capabilities::list_interfaces()) {
		if(iface.type == InterfaceType::WifiVirtualMon || iface.type == InterfaceType::WifiVirtualAP) {
			//log(LogLevel::INFO, "Removing stale {} interface: {}", iface_to_string(iface.type), iface.name);
			//if(iface.type == InterfaceType::WifiVirtualAP)
			//	hw_capabilities::run_cmd({"iw", "dev", iface.name, "ap", "stop"}, nullopt, false);
			hw_capabilities::run_cmd({ "iw", "dev", iface.name, "del" }, nullopt, false);
		}
	}

	cleanup_all_namespaces();
	reset_usb_ifaces();

	parse_requirements();
	log_actor_map("Actors: ", actors);

	// set the regulatory domain before loading the driver so ath9k_htc (user_regd=1)
	// picks it up from the kernel on init instead of falling back to EEPROM.
	auto &g_config = get_global_config();
	if(g_config.contains("regulatory_domain")) {
		const string reg = g_config.at("regulatory_domain").get<string>();
		log(LogLevel::INFO, "Setting regulatory domain pre-USB-reset: iw reg set {}", reg);
		if(hw_capabilities::run_cmd({ "iw", "reg", "set", reg }, nullopt, false) != 0) {
			log(LogLevel::ERROR, "Failed to set regulatory domain {}, NO_IR restrictions may apply", reg);
		} else {
			interruptible_sleep(chrono::milliseconds(100));
		}
	}

	//  external wb/bb separation
	auto external_actors = get_actors(actors, "external");
	ActorCMap external_wb_actors;
	ActorCMap external_bb_actors;

	for(const auto &[name, actor]: external_actors) {
		if(actor->is_external_WB()) {
			external_wb_actors.emplace(name, actor);
		} else if(!_config.at("actors").at(name).value("scan_ignore", false)) {
			external_bb_actors.emplace(name, actor);
		}
	}

	// ------------------ EXTERNAL BLACKBOX -----------------
	// before internal, because need clean interface for scanning
	if(!external_bb_actors.empty()) {
		external_bb_mapping = check_req_options(external_bb_actors, external_bb_options(external_bb_actors));
	}

	// ------------------ INTERNAL ---------------------------
	auto internal_actors = get_actors(actors, "internal");
	if(!internal_actors.empty()) {
		if(!_hw_option_cache.internal_opts.has_value()) _hw_option_cache.internal_opts = internal_options();
		internal_mapping = check_req_options(internal_actors, *_hw_option_cache.internal_opts);
	}

	// ------------------ EXTERNAL WHITEBOX -----------------
	if(!external_wb_actors.empty()) {
		if(!_hw_option_cache.external_wb_opts.has_value()) _hw_option_cache.external_wb_opts = external_wb_options();
		external_wb_mapping = check_req_options(external_wb_actors, *_hw_option_cache.external_wb_opts);

		bool cache_dead = false; // check if cache need reset
		if(_hw_option_cache.external_wb_opts.has_value()) {
			for(const auto &opt: *_hw_option_cache.external_wb_opts) {
				if(opt->conn && !opt->conn->is_connected()) {
					cache_dead = true;
					break;
				}
			}
		}
		if(!_hw_option_cache.external_wb_opts.has_value() || cache_dead)
			_hw_option_cache.external_wb_opts = external_wb_options();
		external_wb_mapping = check_req_options(external_wb_actors, *_hw_option_cache.external_wb_opts);
	}

	// ---------------- SIMULATIONS -------------------------
	auto simulation_actors = get_actors(actors, "simulation");
	if(!simulation_actors.empty()) {
		const auto simulation_options = create_simulation(simulation_actors.size());
		simulation_mapping = check_req_options(simulation_actors, simulation_options);
	}

	//RSSI wizard rssi
	if(!rssi_checked && _config.contains("requirements") && _config.at("requirements").contains("rssi_setup")) {
		//FIXME globally allow/disable wizards , if disabled -> warning
		//TODO add to validator bandwidth / conditions
		auto conditions = _config["requirements"]["rssi_setup"]["conditions"].get<std::vector<std::string>>();

		string cond_str = join(conditions, " && ");
		cond_str = actor_names_to_mac(
				cond_str, { internal_mapping, external_wb_mapping, external_bb_mapping, simulation_mapping });

		auto band = _config["requirements"]["rssi_setup"]["band"].get<std::string>();
		Channel channel;
		if(band == "5GHz") { channel = Channel{ 36, WifiBand::BAND_5, std::nullopt }; }
		if(band == "2_4GHz") { channel = Channel{ 6, WifiBand::BAND_2_4, std::nullopt }; }
		run_rssi_wizard(cond_str, channel);
		rssi_checked = true;

		return true;
	}

	// SETUP ACTORS
	log(LogLevel::DEBUG, "Setup actors, map size: {}", actors.size());

	auto setup_by_map = [&](ActorCMap &actor_map, const ActorMap &mapping) {
		for(auto &[actor_name, actor]: actor_map) actor->setup_actor(_config, mapping.at(actor_name), this);
	};
	log(LogLevel::DEBUG, "Setup internal");
	setup_by_map(internal_actors, internal_mapping);
	log(LogLevel::DEBUG, "Setup external WB");
	setup_by_map(external_wb_actors, external_wb_mapping);
	log(LogLevel::DEBUG, "Setup internal BB");
	setup_by_map(external_bb_actors, external_bb_mapping);
	log(LogLevel::DEBUG, "Setup simulation");
	setup_by_map(simulation_actors, simulation_mapping);

	// --------------- POST-BACKTRACKING REQUIREMENTS
	if(_config.contains("requirements") && _config.at("requirements").contains("two_iface")) {
		for(const auto &[key, actor_names]: _config.at("requirements").at("two_iface").items()) {
			if(!actor_names.is_array() || actor_names.size() < 2)
				throw config_err("two_iface." + key + " must be an array of two actors");

			const ActorPtr &actor1 = get_actor(actor_names[0].get<string>());
			const ActorPtr &actor2 = get_actor(actor_names[1].get<string>());

			const auto cb = get_global_config().value("use_two_iface_cache", true) ? run_on_miss : force_run;
			if(key == "active") {
				if(TwoIfaceActive::run_check(actor1, actor2, cb)) return true;
			} else if(key.starts_with("injection")) {
				if(TwoIfaceInject::run_check(actor1, actor2, cb, key)) return true;
			} else {
				throw not_implemented_err("two_iface test key not found: " + key);
			}
		}
	}
	return false;
}
//TODO test
string RunStatus::get_filler_hash(const ActorMap &actor_map, json &test_cfg) {
	// build stable hash from sorted actor_name=perm_mac pairs
	vector<string> mac_parts;
	for(const auto &[actor_name, hw]: actor_map) {
		const auto &perm_mac = (*hw)[SK::permanent_mac];
		if(!perm_mac.has_value()) continue;
		mac_parts.push_back(actor_name + "=" + *perm_mac);
		test_cfg["actors"][actor_name]["selection"]["permanent_mac"] = *perm_mac;
	}
	ranges::sort(mac_parts);
	string mac_concat;
	for(const auto &p: mac_parts) mac_concat += p;
	ostringstream oss;
	oss << hex << hash<string>{}(join(mac_parts));
	string hash_str = oss.str().substr(0, 8);
	return hash_str;
}

//TODO test
void RunStatus::change_filler_hash(const ActorMap &result) {
	if(_config_path.filename().string().find(visual::helper::ACTOR_FILLER_SUFFIX) == string::npos)
		return;

	const string current_name = _config.at("name").get<string>();
	const auto sep = current_name.rfind('_');
	if(sep == string::npos) throw run_err("change_test_hash");

	const string base_name = current_name.substr(0, sep);
	const string old_hash = current_name.substr(sep + 1);
	string new_hash = get_filler_hash(result, _config);
	if(new_hash == old_hash) throw run_err("change_test_hash");

	const string new_name = format("{}_{}", base_name, new_hash);

	const path new_folder = _run_folder.parent_path() / new_name;
	filesystem::rename(_run_folder, new_folder);
	_run_folder = new_folder;

	const path new_config_path = _config_path.parent_path() / (new_hash + visual::helper::ACTOR_FILLER_SUFFIX);
	_config["name"] = new_name;
	filesystem::remove(_config_path);
	save_yaml(_config, new_config_path);
	set_public_perms(new_config_path);
	config_validation(new_config_path);
	_config_path = new_config_path;
}

ActorMap RunStatus::check_req_options(const ActorCMap &rules, const vector<ActorPtr> &options, const bool print) {
	vector<string> ruleKeys;
	for(const auto &key: rules | views::keys) {
		ruleKeys.push_back(key);
	}

	ActorMap result;
	if(unordered_set<size_t> usedOptions; hw_capabilities::find_solution(ruleKeys, 0, rules, options, usedOptions, result)) {
		change_filler_hash(result); // if actor filler test

		if(print) {
			log(LogLevel::DEBUG, "Solved!");
			for(auto const &[r, o]: result) log(LogLevel::DEBUG, "Rule {} -> option {}", r, o->to_str());
		}
		return result;
	}
	if(print) {
		Actor_config::print_ActorCMap("Actor rules", rules);
		Actor_config::print_ActorCMap("Actor options", options);
	}
	throw req_err("Not found valid requirements: {}", hw_capabilities::get_heuristic_err_msg(rules, options));
}


}
