#include <nlohmann/json.hpp>
#include <tins/hw_address.h>
#include "attacks/Enterprise/eap_pwd_reflection.h"
#include "attacks/mc_mitm/MonitorSocket.h"
#include "config/RunStatus.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "setup/program.h"
#include "system/ip.h"
#include "system/utils.h"

using namespace std;
using namespace filesystem;
using namespace Tins;

namespace wpa3_tester::reflection{

void setup_attack(RunStatus &rs){
	copy_file(rs.config_path().parent_path() / "config/hostapd.eap_user",
			  rs.run_folder() / "hostapd.eap_user");
	set_public_perms(rs.run_folder() / "hostapd.eap_user");

	program::start(rs, "access_point");
	rs.process_manager.wait_for("access_point", "AP-ENABLED", chrono::seconds(40));
	log(LogLevel::INFO, "access_point running");
	ip::set_ip(rs, "access_point");

	//const auto attacker = rs.get_actor("attacker");
	//attacker->set_monitor_mode();
	//attacker->set_iface_up();
	//log(LogLevel::INFO, "attacker interface in monitor mode");

}

void run_attack(RunStatus &rs){
	rs.start_observers();
	const auto &att_cfg  = rs.config().at("attack_config");
	const auto attacker  = rs.get_actor("attacker");
	const auto ap_actor  = rs.get_actor("access_point");

	const string iface      = attacker.get(SK::iface);
	const string identity   = att_cfg.at("identity").get<string>();
	const string ssid       = ap_actor->get(SK::ssid);
	const Channel channel   = ap_actor->get_channel();

	const HWAddress<6> our_mac(attacker.get(SK::mac));
	const HWAddress<6> ap_mac(ap_actor.get(SK::mac));
    
	MonitorSocket sock(iface);

	const bool vulnerable = run_reflection_exchange(
		sock, channel, our_mac, ap_mac, ssid, identity, chrono::seconds(30));

	nlohmann::json j;
	j["passed"] = vulnerable;
	rs.save_result(j);
	log(LogLevel::INFO, "Reflection attack result: {}", vulnerable ? "VULNERABLE" : "not vulnerable");
}

/*void stats(const RunStatus& rs){
}*/
}