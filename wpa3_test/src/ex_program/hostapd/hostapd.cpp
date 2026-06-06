#include "ex_program/hostapd/hostapd.h"
#include <filesystem>
#include <fstream>
#include "ex_program/hostapd/hostapd_helper.h"

#include "logger/error_log.h"
#include "logger/log.h"
#include "observer/observers.h"
#include "system/utils.h"

namespace wpa3_tester::hostapd{
using namespace std;
using namespace filesystem;
using namespace nlohmann;

static string get_field_or_parse(const json &program_config, const string &key, const string &config_path, bool is_int,
								const function<string(const string &)> &parse_from_file
){
	if(program_config.contains(key)){
		if(is_int) return to_string(program_config[key].get<int>());
		return program_config[key].get<string>();
	}
	if(!config_path.empty()){
		try{
			return parse_from_file(config_path);
		} catch(...){}
	}
	throw config_err("Field '" + key + "' not found in config or file: " + config_path);
}

static string parse_key_from_file(const string &config_path, const string &key){
	ifstream f(config_path);
	string line;
	while(getline(f, line)){
		if(line.starts_with(key + "=")) return line.substr(key.size() + 1);
	}
	throw config_err("Key '" + key + "' not found in file: " + config_path);
}

string get_ssid(const json &program_config, const string &config_path){
	return get_field_or_parse(program_config, "ssid", config_path, false,
							[](const string &p){ return parse_key_from_file(p, "ssid"); });
}

string get_channel(const json &program_config, const string &config_path){
	return get_field_or_parse(program_config, "channel", config_path, true,
							[](const string &p){ return parse_key_from_file(p, "channel"); });
}

// --------------- HOSTAPD -----------------------

static void write_hostapd_kv(ofstream &out, const json &setup){
	static const set<string> skip = {"hostapd_path", "version", "other_options"};
	for(auto it = setup.begin(); it != setup.end(); ++it){
		if(skip.contains(it.key())) continue;
		out << it.key() << "=";
		if(it.value().is_string()) out << it.value().get<string>();
		else out << it.value().dump();
		out << "\n";
	}
}

string hostapd_config(const string &run_folder, const string &actor_name, const json &ap_setup,
					const path &config_folder
){
	path folder(run_folder);
	path cfg_path = folder / (actor_name + "_hostapd.conf");

	error_code ec;
	create_directories(folder, ec);
	if(ec){
		log(LogLevel::ERROR, "hostapd_config: failed to ensure run folder: {}:{}", folder.string(), ec.message());
		throw run_err("hostapd_config: unable to create run folder");
	}

	if(ap_setup.contains("hostapd_path")){
		path hostapd_path = ap_setup["hostapd_path"].get<string>();
		path src = hostapd_path.is_absolute() ? hostapd_path : config_folder / hostapd_path;
		copy_f(src, cfg_path);
		ofstream out(cfg_path, ios::app);
		write_hostapd_kv(out, ap_setup);
	} else {
		ofstream out(cfg_path);
		if(!out){
			log(LogLevel::ERROR, "hostapd_config: failed to open config file: {}", cfg_path.string());
			throw run_err("hostapd_config: unable to open config file");
		}
		write_hostapd_kv(out, ap_setup);
	}

	set_public_perms(cfg_path);
	log(LogLevel::INFO, "hostapd_config: written {}", cfg_path.string());
	return cfg_path.string();
}

void run_hostapd(RunStatus &rs, const string &actor_name){
	json program_config = rs.config().at("actors").at(actor_name).at("setup").at("program_config");
	const string hostapd_config_path = hostapd_config(rs.run_folder(), actor_name, program_config,
													rs.config_path().parent_path());
	rs.get_actor(actor_name)->set(SK::ssid, get_ssid(program_config, hostapd_config_path));
	rs.get_actor(actor_name)->set(SK::channel, get_channel(program_config, hostapd_config_path));

	string version;
	if(program_config.contains("version") && !program_config["version"].is_null()){
		version = program_config["version"].get<string>();
	}

	vector<string> command = {};
	observer::add_nets_header(rs, command, actor_name);

	command.insert(command.end(), {
						get_hostapd(version), "-i", rs.get_actor(actor_name)["iface"], hostapd_config_path,
					});
	if(program_config.contains("other_options") && !program_config["other_options"].is_null()){
		istringstream ss(program_config["other_options"].get<string>());
		string token;
		while(ss >> token) command.push_back(token);
	}
	rs.process_manager.run(actor_name, command, rs.run_folder());
}

// --------- WPA_SUPPLICANT ---------------

static const set<string> wpa_global_keys = {"okc", "pmf", "ctrl_interface", "eapol_version"};
static const set<string> wpa_quoted_keys = {"ssid", "sae_password", "psk", "identity", "password"};
static const set<string> wpa_skip_keys   = {"wpa_supplicant_path", "version", "other_options"};

static string wpa_network_fmt(const string &key, const json &val){
	if(val.is_string() && !wpa_quoted_keys.contains(key)) return val.get<string>();
	return val.dump();
}

static void write_wpa_global_kv(ofstream &out, const json &setup){
	for(auto it = setup.begin(); it != setup.end(); ++it){
		if(!wpa_global_keys.contains(it.key())) continue;
		out << it.key() << "=" << it.value().dump() << "\n";
	}
}

static void write_wpa_network_block(ofstream &out, const json &setup){
	out << "network={\n";
	for(auto it = setup.begin(); it != setup.end(); ++it){
		if(wpa_skip_keys.contains(it.key())) continue;
		if(wpa_global_keys.contains(it.key())) continue;
		out << "\t" << it.key() << "=" << wpa_network_fmt(it.key(), it.value()) << "\n";
	}
	out << "}\n";
}

// rewrites cfg in-place, replacing matched keys and injecting new ones.
static void apply_wpa_overrides(const path &cfg, const json &overrides){
	map<string, string> global_ov, network_ov;
	for(auto it = overrides.begin(); it != overrides.end(); ++it){
		if(wpa_skip_keys.contains(it.key())) continue;
		if(wpa_global_keys.contains(it.key()))
			global_ov[it.key()] = it.value().dump();
		else
			network_ov[it.key()] = wpa_network_fmt(it.key(), it.value());
	}
	if(global_ov.empty() && network_ov.empty()) return;

	ifstream in(cfg);
	vector<string> lines;
	string line;
	while(getline(in, line)) lines.push_back(line);
	in.close();

	bool in_block = false, block_seen = false;
	set<string> w_global, w_network;

	ofstream out(cfg);
	for(auto &l : lines){
		string s = l;
		s.erase(0, s.find_first_not_of(" \t"));
		if(auto last = s.find_last_not_of(" \t\r\n"); last != string::npos) s.erase(last + 1);
		else s.clear();

		if(s == "network={"){
			block_seen = in_block = true;
			for(auto &[k, v] : global_ov)
				if(w_global.insert(k).second) out << k << "=" << v << "\n";
			out << l << "\n";
			continue;
		}
		if(in_block && s == "}"){
			in_block = false;
			for(auto &[k, v] : network_ov)
				if(w_network.insert(k).second) out << "\t" << k << "=" << v << "\n";
			out << l << "\n";
			continue;
		}

		if(auto eq = s.find('='); eq != string::npos){
			string key = s.substr(0, eq);
			if(!in_block && global_ov.count(key)){
				if(w_global.insert(key).second) out << key << "=" << global_ov.at(key) << "\n";
				continue;
			}
			if(in_block && network_ov.count(key)){
				if(w_network.insert(key).second) out << "\t" << key << "=" << network_ov.at(key) << "\n";
				continue;
			}
		}
		out << l << "\n";
	}

	// no network={} block in file: append globals then a new network block
	if(!block_seen){
		for(auto &[k, v] : global_ov)
			if(!w_global.count(k)) out << k << "=" << v << "\n";
		if(!network_ov.empty()){
			out << "network={\n";
			for(auto &[k, v] : network_ov) out << "\t" << k << "=" << v << "\n";
			out << "}\n";
		}
	}
}

string wpa_supplicant_config(const string &run_folder, const string &actor_name, const json &client_setup,
							const path &config_folder
){
	path folder(run_folder);
	path cfg_path = folder / (actor_name + "_wpa_supplicant.conf");

	error_code ec;
	create_directories(folder, ec);
	if(ec){
		log(LogLevel::ERROR, "wpa_supplicant_config: failed to ensure run folder: {}: {}", run_folder, ec.message());
		throw run_err("wpa_supplicant_config: unable to create run folder");
	}

	if(client_setup.contains("wpa_supplicant_path")){
		path src_path = client_setup["wpa_supplicant_path"].get<string>();
		path src = src_path.is_absolute() ? src_path : config_folder / src_path;
		copy_f(src, cfg_path);
		apply_wpa_overrides(cfg_path, client_setup);
	} else {
		ofstream out(cfg_path);
		if(!out){
			log(LogLevel::ERROR, "wpa_supplicant_config: failed to open config file: {}", cfg_path.string());
			throw run_err("wpa_supplicant_config: unable to open config file");
		}
		write_wpa_global_kv(out, client_setup);
		write_wpa_network_block(out, client_setup);
	}

	set_public_perms(cfg_path);
	log(LogLevel::INFO, "wpa_supplicant_config: written {}", cfg_path.string());
	return cfg_path.string();
}

void run_wpa_supplicant(RunStatus &rs, const string &actor_name){
	json program_config = rs.config().at("actors").at(actor_name).at("setup").at("program_config");

	string version;
	if(program_config.contains("version") && !program_config["version"].is_null()){
		version = program_config["version"].get<string>();
	}

	const string wpa_supp_config_path = wpa_supplicant_config(rs.run_folder(), actor_name, program_config,
															rs.config_path().parent_path());

	vector<string> command = {};
	observer::add_nets_header(rs, command, actor_name);

	command.insert(command.end(), {
						get_wpa_supplicant(version), "-i", rs.get_actor(actor_name)["iface"], "-c", wpa_supp_config_path
					});
	if(program_config.contains("other_options") && !program_config["other_options"].is_null()){
		istringstream ss(program_config["other_options"].get<string>());
		string token;
		while(ss >> token) command.push_back(token);
	}
	rs.process_manager.run(actor_name, command, rs.run_folder());
}

// --------- HOSTAPD_MANA ---------
void run_hostapd_mana(RunStatus &rs, const string &actor_name){
	const path hostapd_mana_config_path = rs.run_folder()/ (actor_name + "_hostapd_mana.conf");

	const json program_config = rs.config().at("actors").at(actor_name).at("setup").at("program_config");
	if(program_config.contains("hostapd-mana_path")){
		const path hostapd_path = program_config["hostapd-mana_path"].get<string>();
		const path src = hostapd_path.is_absolute() ? hostapd_path : rs.config_path().parent_path() / hostapd_path;
		copy_f(src, hostapd_mana_config_path);
	}

	if(rs.get_actor(actor_name)["source"] == "internal"){
		rs.get_actor(actor_name)->set(SK::ssid, get_ssid(program_config, hostapd_mana_config_path));
		rs.get_actor(actor_name)->set(SK::channel, get_channel(program_config, hostapd_mana_config_path));
	}

	string version;
	if(program_config.contains("version") && !program_config["version"].is_null()){
		version = program_config["version"].get<string>();
	}

	vector<string> command = {};
	observer::add_nets_header(rs, command, actor_name);

	command.insert(command.end(), {
						get_hostapd_mana(version),
						//"-P", pid_file, // write PID to file, don't work without -B (background)
						"-i", rs.get_actor(actor_name)["iface"], hostapd_mana_config_path,
					});

	const path log_path = rs.run_folder() / "logger" / (actor_name + ".log");
	const path output_path = rs.run_folder() / "captured_hashes.txt";

	rs.process_manager.run(actor_name, command, rs.run_folder());
	// parsing hashes - bypass, but mana_wpaout don't works n NIxOS (some low level protection?)
	rs.process_manager.after_stop(actor_name, [log_path, output_path](){
		ifstream log_file(log_path);
		if(!log_file.is_open()) return;

		ofstream out(output_path);
		string line;
		set<string> seen;
		while(getline(log_file, line)){
			const auto pos = line.find("MANA WPA2 HASHCAT | ");
			if(pos == string::npos) continue;
			const string hash = line.substr(pos + 20);
			if(seen.insert(hash).second){
				out << hash << "\n";
				log(LogLevel::INFO, "Captured hash: {}...", hash.substr(0, 32));
			}
		}
		if(exists(output_path)) set_public_perms(output_path);
	});
}
}