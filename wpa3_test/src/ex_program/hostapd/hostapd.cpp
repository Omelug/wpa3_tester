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

// --------------- HOSTAPD -----------------------

static void write_hostapd_kv(ofstream &out, const json &setup){
	static const set<string> skip = {"hostapd_path", "hostapd-mana_path", "version", "openssl", "other_options"};
	for (const auto& [key, val] : setup.items()) {
		if (skip.contains(key)) continue;
    
		out << key << "=";
		if (val.is_string()) out << val.get<string>();
		else out << val.dump();
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
	} else{
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

static const set<string> owe_trans_skip = {
	"owe_transition_mode", "open_ssid", "owe_ssid",
	"hostapd_path", "version", "openssl", "other_options"
};
static const set<string> owe_bss_only = {
	"wpa", "wpa_key_mgmt", "rsn_pairwise", "ieee80211w",
	"rsn_group_mgmt_cipher", "group_mgmt_cipher", "wpa_psk", "wpa_passphrase",
	"sae_password", "sae_groups"
};

static string hostapd_owe_trans_config(RunStatus &rs, const string &actor_name){
	const json &pc = rs.config().at("actors").at(actor_name).at("setup").at("program_config");
	const string primary_mac = rs.get_actor(actor_name).get(SK::mac);
	const string primary_iface = rs.get_actor(actor_name).get(SK::iface);
	const string secondary_bssid = owe_trans_bssid(primary_mac);
	const string secondary_iface = primary_iface.substr(0, 11) + "_owe"; // Linux iface name <= 15 chars
	const string open_ssid = pc.at("open_ssid").get<string>();
	const string owe_ssid = pc.at("owe_ssid").get<string>();

	path cfg_path = path(rs.run_folder()) / (actor_name + "_hostapd.conf");
	error_code ec;
	create_directories(rs.run_folder(), ec);
	if(ec) throw run_err("hostapd_owe_trans_config: unable to create run folder");
	ofstream out(cfg_path);
	if(!out) throw run_err("hostapd_owe_trans_config: unable to open config file");

	// ---- primary (open) BSS
	for (const auto& [key, val] : pc.items()) {
		if(owe_trans_skip.contains(key) || owe_bss_only.contains(key)) continue;
		out << key << "=";
		if(val.is_string()) out << val.get<string>(); else out << val.dump();
		out << "\n";
	}
	out << "ssid=" << open_ssid << "\n"
		<< "owe_transition_bssid=" << secondary_bssid << "\n"
		<< "owe_transition_ssid=\"" << owe_ssid << "\"\n\n";

	// ---- secondary (OWE) BSS
	out << "bss=" << secondary_iface << "\n"
		<< "bssid=" << secondary_bssid << "\n"
		<< "ssid=" << owe_ssid << "\n";
	for (const auto& [key, val] : pc.items()) {
		if(!owe_bss_only.contains(key)) continue;
		out << key << "=";
		if(val.is_string()) out << val.get<string>(); else out << val.dump();
		out << "\n";
	}
	out << "owe_transition_bssid=" << primary_mac << "\n"
		<< "owe_transition_ssid=\"" << open_ssid << "\"\n";

	out.close();
	set_public_perms(cfg_path);
	log(LogLevel::INFO, "hostapd_owe_trans_config: written {} (open={}, owe={})",
		cfg_path.string(), open_ssid, owe_ssid);
	return cfg_path.string();
}

void run_hostapd(RunStatus &rs, const string &actor_name){
	json program_config = rs.config().at("actors").at(actor_name).at("setup").at("program_config");

	string hostapd_config_path;
	if(program_config.value("owe_transition_mode", false)){
		hostapd_config_path = hostapd_owe_trans_config(rs, actor_name);
		rs.get_actor(actor_name)->set(SK::ssid, program_config.at("owe_ssid").get<string>());
	} else{
		hostapd_config_path = hostapd_config(rs.run_folder(), actor_name, program_config,
											rs.config_path().parent_path());
		rs.get_actor(actor_name)->set(SK::ssid, get_ssid(rs, actor_name));
	}
	rs.get_actor(actor_name)->set(SK::channel, get_channel(program_config, hostapd_config_path));

	string version;
	if(program_config.contains("version") && !program_config["version"].is_null()){
		version = program_config["version"].get<string>();
	}

	vector<string> command = {};
	observer::add_nets_header(rs, command, actor_name);

	string hostapd_bin;
	if(program_config.contains("openssl") && !program_config["openssl"].is_null()){
		const string openssl_version = program_config["openssl"].get<string>();
		const OpenSSLPaths ssl = get_openssl_paths(openssl_version);
		command.insert(command.end(), {
							"env", "LD_LIBRARY_PATH=" + ssl.lib_dir.string(), "LD_PRELOAD=" + ssl.libcrypto.string(),
						});
		hostapd_bin = get_hostapd_with_openssl(version, openssl_version);
	} else{
		hostapd_bin = get_hostapd(version);
	}

	command.insert(command.end(), {hostapd_bin, "-i", rs.get_actor(actor_name).get(SK::iface), hostapd_config_path,});
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
static const set<string> wpa_skip_keys = {"wpa_supplicant_path", "version", "other_options"};

static string wpa_network_fmt(const string &key, const json &val){
	if(val.is_string() && !wpa_quoted_keys.contains(key)) return val.get<string>();
	return val.dump();
}

static void write_wpa_global_kv(ofstream &out, const json &setup){
	for (const auto& [key, val] : setup.items()) {
		if(!wpa_global_keys.contains(key)) continue;
		out << key << "=" << val.dump() << "\n";
	}
}

static void write_wpa_network_block(ofstream &out, const json &setup){
	out << "network={\n";
	for (const auto& [key, val] : setup.items()) {
		if(wpa_skip_keys.contains(key)) continue;
		if(wpa_global_keys.contains(key)) continue;
		out << "\t" << key << "=" << wpa_network_fmt(key, val) << "\n";
	}
	out << "}\n";
}

void apply_wpa_overrides(const path &cfg, const json &overrides){
	map<string,string> global_ov, network_ov;
	for (const auto& [key, val] : overrides.items()) {
		if(wpa_skip_keys.contains(key)) continue;
		if(wpa_global_keys.contains(key)) global_ov[key] = val.dump();
		else network_ov[key] = wpa_network_fmt(key, val);
	}
	if(global_ov.empty() && network_ov.empty()) return;

	ifstream in(cfg);
	vector<string> lines;
	string line;
	while(getline(in, line)) lines.push_back(line);

	bool in_block = false, block_seen = false;

	ofstream out(cfg);
	for(auto &l: lines){
		string s = trim(l);

		if(s == "network={"){
			block_seen = in_block = true;
			for(auto &[k, v]: global_ov) out << k << "=" << v << "\n";
			global_ov.clear();
			out << l << "\n";
			continue;
		}
		if(in_block && s == "}"){
			in_block = false;
			for(auto &[k, v]: network_ov) out << "\t" << k << "=" << v << "\n";
			network_ov.clear();
			out << l << "\n";
			continue;
		}

		if(auto eq = s.find('='); eq != string::npos){
			string key = s.substr(0, eq);
			if(!in_block){
				if(auto it = global_ov.find(key); it != global_ov.end()){
					out << key << "=" << it->second << "\n";
					global_ov.erase(it);
					continue;
				}
			} else {
				if(auto it = network_ov.find(key); it != network_ov.end()){
					out << "\t" << key << "=" << it->second << "\n";
					network_ov.erase(it);
					continue;
				}
			}
		}
		out << l << "\n";
	}

	if(!block_seen){
		for(auto &[k, v]: global_ov) out << k << "=" << v << "\n";
		if(!network_ov.empty()){
			out << "network={\n";
			for(auto &[k, v]: network_ov) out << "\t" << k << "=" << v << "\n";
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
	} else{
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
						get_wpa_supplicant(version), "-i", rs.get_actor(actor_name).get(SK::iface), "-c", wpa_supp_config_path
					});
	if(program_config.contains("other_options") && !program_config["other_options"].is_null()){
		istringstream ss(program_config["other_options"].get<string>());
		string token;
		while(ss >> token) command.push_back(token);
	}
	rs.process_manager.run(actor_name, command, rs.run_folder());
}

// --------- HOSTAPD_MANA ---------

static string hostapd_mana_config(const string &run_folder, const string &actor_name, const json &ap_setup,
								const path &config_folder
){
	path folder(run_folder);
	path cfg_path = folder / (actor_name + "_hostapd_mana.conf");

	error_code ec;
	create_directories(folder, ec);
	if(ec) throw run_err("hostapd_mana_config: unable to create run folder");

	if(ap_setup.contains("hostapd-mana_path")){
		path src_path = ap_setup["hostapd-mana_path"].get<string>();
		path src = src_path.is_absolute() ? src_path : config_folder / src_path;
		copy_f(src, cfg_path);
		ofstream out(cfg_path, ios::app);
		write_hostapd_kv(out, ap_setup);
	} else{
		ofstream out(cfg_path);
		if(!out) throw run_err("hostapd_mana_config: unable to open config file");
		write_hostapd_kv(out, ap_setup);
	}

	set_public_perms(cfg_path);
	log(LogLevel::INFO, "hostapd_mana_config: written {}", cfg_path.string());
	return cfg_path.string();
}


void run_hostapd_mana(RunStatus &rs, const string &actor_name){
	const json program_config = rs.config().at("actors").at(actor_name).at("setup").at("program_config");
	const string mana_config_path = hostapd_mana_config(rs.run_folder(), actor_name, program_config,
														rs.config_path().parent_path());

	if(rs.get_actor(actor_name)["source"] == "internal"){
		rs.get_actor(actor_name)->set(SK::ssid, get_ssid(rs, actor_name));
		rs.get_actor(actor_name)->set(SK::channel, get_channel(program_config, mana_config_path));
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
						"-i", rs.get_actor(actor_name).get(SK::iface), mana_config_path,
					});

	const path run_folder_path(rs.run_folder());
	const path log_path = run_folder_path / "logger" / (actor_name + ".log");
	const path output_path = run_folder_path / "captured_hashes.txt";
	const path hccapx_path = run_folder_path / "mana_handshakes.hccapx";
	const path mana_22000 = run_folder_path / "hostapd-mana.22000";

	rs.process_manager.run(actor_name, command, rs.run_folder());
	rs.process_manager.after_stop(actor_name, [log_path, output_path, hccapx_path, mana_22000, run_folder_path](){
		ofstream out(output_path);
		set<string> seen;
		auto add = [&](const string &hash){
			if(!hash.empty() && seen.insert(hash).second){
				out << hash << "\n";
				log(LogLevel::INFO, "Captured hash: {}...", hash.substr(0, 32));
			}
		};

		//FIXME crackable from different sources(not priority now )
		/*if(exists(mana_22000)){
			ifstream f(mana_22000);
			string line;
			while(getline(f, line)){
			   if(line.starts_with("WPA*")){
			   		add(line);
				}
			}
		}
		if(exists(hccapx_path)){
		   for(const auto &h: hccapx_to_wpa_hashes(hccapx_path)){
			   add(h);
		   }
		}*/
		if(exists(log_path)) {
		   ifstream log_file(log_path);
		   string line;
		   while(getline(log_file, line)){
			  const auto pos = line.find("MANA WPA2 HASHCAT | ");
			  if(pos == string::npos) continue;
			  add(line.substr(pos + 20));
		   }
		}

		if(exists(output_path)) set_public_perms(output_path);
	});
}
}