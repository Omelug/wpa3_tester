#include "attacks/components/setup_connections.h"
#include "config/global_config.h"
#include "config/RunStatus.h"
#include "logger/error_log.h"
#include "observer/observers.h"
#include "system/hw_capabilities.h"
#include "system/utils.h"

using namespace std;
using namespace filesystem;

namespace wpa3_tester::reflection_dragonslayer{

void setup_attack(RunStatus &rs){
	const auto target_type = rs.config().at("attack_config").at("target_type").get<string>();
	assert(target_type == "ap" || target_type == "sta");
	if(target_type == "ap"){
		copy_f(rs.config_path().parent_path() / "config/dragonslayer-wpa_supplicant.conf",
				rs.run_folder()/ "dragonslayer.conf");
	}
	if(target_type == "sta"){
		copy_f(rs.config_path().parent_path() / "config/dragonslayer-hostapd.conf",
				rs.run_folder()/ "dragonslayer.conf");
	}
	copy_f(rs.config_path().parent_path() / "config/hostapd.eap_user", rs.run_folder()/ "hostapd.eap_user");
	components::client_ap_attacker_setup_enterprise(rs);
}

void start_dragonslayer(RunStatus &rs, const string &actor_name, const string &iface, const string &target_type){
	assert(target_type == "ap" || target_type == "sta");
	vector<string> command = {};
	observer::add_nets_header(rs, command, actor_name);
	const string dragonslayer_folder = get_global_config().at("paths").at("dragonslayer").at("dragonslayer_folder");
	// TODO compile dragonslayer, if not compiled

	if(target_type == "ap"){
		command.insert(command.end(), {
							dragonslayer_folder + "/wpa_supplicant/wpa_supplicant", "-D", "nl80211", "-c",
							rs.run_folder()/ "dragonslayer.conf", "-i", iface, "-a", "0"
						});
	}
	if(target_type == "sta"){
		throw not_implemented_err("adwada");
	}
	rs.process_manager.run(actor_name, command, path(dragonslayer_folder) / "dragonslayer");
}

void run_attack(RunStatus &rs){
	const auto &att_cfg = rs.config().at("attack_config");
	const auto attacker = rs.get_actor("attacker");
	const auto target_type = att_cfg.at("target_type").get<string>();
	start_dragonslayer(rs, attacker.get(SK::actor_name), attacker.get(SK::iface), target_type);

	ofstream attack_result(rs.run_folder()/ "result.txt");
	attack_result << to_string(
		rs.process_manager.wait_for("attacker", "server is vulnerable to reflection", chrono::seconds(40), false));
	attack_result.close();
	set_public_perms(rs.run_folder()/ "result.txt");
}

/*void stats(const RunStatus& rs){
}*/
}