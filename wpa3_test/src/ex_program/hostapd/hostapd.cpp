#include "ex_program/hostapd/hostapd.h"
#include <cstring>
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

void run_hostapd(RunStatus &rs, const string &actor_name){
	json program_config = rs.config().at("actors").at(actor_name).at("setup").at("program_config");
	const string hostapd_config_path = hostapd_config(rs.run_folder(), actor_name, program_config,
													rs.config_path().parent_path());
	rs.get_actor(actor_name)->set(SK::ssid, get_ssid(rs, actor_name));
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

	command.insert(command.end(), {hostapd_bin, "-i", rs.get_actor(actor_name)["iface"], hostapd_config_path,});
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
	map<string,string> global_ov, network_ov;
	for(auto it = overrides.begin(); it != overrides.end(); ++it){
		if(wpa_skip_keys.contains(it.key())) continue;
		if(wpa_global_keys.contains(it.key())) global_ov[it.key()] = it.value().dump();
		else network_ov[it.key()] = wpa_network_fmt(it.key(), it.value());
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
	for(auto &l: lines){
		string s = l;
		s.erase(0, s.find_first_not_of(" \t"));
		if(auto last = s.find_last_not_of(" \t\r\n"); last != string::npos) s.erase(last + 1);
		else s.clear();

		if(s == "network={"){
			block_seen = in_block = true;
			for(auto &[k, v]: global_ov) if(w_global.insert(k).second) out << k << "=" << v << "\n";
			out << l << "\n";
			continue;
		}
		if(in_block && s == "}"){
			in_block = false;
			for(auto &[k, v]: network_ov) if(w_network.insert(k).second) out << "\t" << k << "=" << v << "\n";
			out << l << "\n";
			continue;
		}

		if(auto eq = s.find('='); eq != string::npos){
			string key = s.substr(0, eq);
			if(!in_block && global_ov.contains(key)){
				if(w_global.insert(key).second) out << key << "=" << global_ov.at(key) << "\n";
				continue;
			}
			if(in_block && network_ov.contains(key)){
				if(w_network.insert(key).second) out << "\t" << key << "=" << network_ov.at(key) << "\n";
				continue;
			}
		}
		out << l << "\n";
	}

	// no network={} block in file: append globals then a new network block
	if(!block_seen){
		for(auto &[k, v]: global_ov) if(!w_global.contains(k)) out << k << "=" << v << "\n";
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

static string hex_encode(const uint8_t *data, size_t len){
	static constexpr char HEX[] = "0123456789abcdef";
	string out;
	out.reserve(len * 2);
	for(size_t i = 0; i < len; ++i){ out += HEX[(data[i] >> 4) & 0xf]; out += HEX[data[i] & 0xf]; }
	return out;
}

// Parse hccapx v4 written by hostapd-mana (mana_wpaout) and convert to WPA*02* lines
static vector<string> hccapx_to_wpa_hashes(const path &hccapx_path){
	ifstream f(hccapx_path, ios::binary);
	if(!f) return {};
	vector<string> hashes;
	while(f){
		uint8_t sig[8];
		if(!f.read(reinterpret_cast<char *>(sig), 8)) break;
		if(memcmp(sig, "HCPX\x04\x00\x00\x00", 8) != 0) break;
		uint8_t msg_pair, ssid_len, ssid[32], keyver, mic[16], mac_ap[6], anonce[32], mac_sta[6], snonce[32];
		uint16_t eapol_len;
		uint8_t eapol[256];
		f.read(reinterpret_cast<char *>(&msg_pair), 1);
		f.read(reinterpret_cast<char *>(&ssid_len), 1);
		f.read(reinterpret_cast<char *>(ssid), 32);
		f.read(reinterpret_cast<char *>(&keyver), 1);
		f.read(reinterpret_cast<char *>(mic), 16);
		f.read(reinterpret_cast<char *>(mac_ap), 6);
		f.read(reinterpret_cast<char *>(anonce), 32);
		f.read(reinterpret_cast<char *>(mac_sta), 6);
		f.read(reinterpret_cast<char *>(snonce), 32);
		f.read(reinterpret_cast<char *>(&eapol_len), 2);
		f.read(reinterpret_cast<char *>(eapol), 256);
		if(!f) break;
		const size_t eapol_sz = min(static_cast<size_t>(eapol_len), size_t{256});
		hashes.push_back("WPA*02*" + hex_encode(mic, 16) + "*" + hex_encode(mac_ap, 6) + "*" +
						 hex_encode(mac_sta, 6) + "*" + hex_encode(ssid, ssid_len) + "*" +
						 hex_encode(anonce, 32) + "*" + hex_encode(eapol, eapol_sz) + "*" +
						 hex_encode(&msg_pair, 1));
	}
	return hashes;
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
						"-i", rs.get_actor(actor_name)["iface"], mana_config_path,
					});

	const path log_path = rs.run_folder() / "logger" / (actor_name + ".log");
	const path output_path = rs.run_folder() / "captured_hashes.txt";
	const path hccapx_path = rs.run_folder() / "mana_handshakes.hccapx";

	rs.process_manager.run(actor_name, command, rs.run_folder());
	rs.process_manager.after_stop(actor_name, [log_path, output_path, hccapx_path](){
		ofstream out(output_path);
		set<string> seen;
		auto add = [&](const string &hash){
			if(!hash.empty() && seen.insert(hash).second){
				out << hash << "\n";
				log(LogLevel::INFO, "Captured hash: {}...", hash.substr(0, 32));
			}
		};

		// mana_wpaout path: hostapd-mana 2.10+ with mana_wpaout writes hccapx
		for(const auto &h: hccapx_to_wpa_hashes(hccapx_path)) add(h);

		// fallback: older/patched MANA logging "MANA WPA2 HASHCAT | WPA*02*..."
		ifstream log_file(log_path);
		string line;
		while(getline(log_file, line)){
			const auto pos = line.find("MANA WPA2 HASHCAT | ");
			if(pos == string::npos) continue;
			add(line.substr(pos + 20));
		}

		if(exists(output_path)) set_public_perms(output_path);
	});
}
}