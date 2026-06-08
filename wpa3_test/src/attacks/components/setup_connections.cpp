#include "config/RunStatus.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "setup/program.h"
#include "system/ip.h"
#include "system/utils.h"

using namespace std;
using namespace chrono;

namespace wpa3_tester::components{
void setup_AP(RunStatus &rs, const string &actor_name){
	program::start(rs, actor_name);

	//FIXME this dont work with external logread  (some issue with buffering?)
	// rs.process_manager.wait_for(actor_name, "AP-ENABLED", chrono::seconds(40));

	log(LogLevel::INFO, "{} is running", actor_name);
	if(rs.get_actor(actor_name)[SK::ip_addr]){
		ip::set_ip(rs, actor_name);
	}
}

void setup_STA(RunStatus &rs, const string &actor_name){
	program::start(rs, actor_name);
	rs.process_manager.wait_for(actor_name, "Successfully initialized wpa_supplicant", seconds(10));
	if(rs.get_actor(actor_name)[SK::ip_addr]){
		ip::set_ip(rs, actor_name);
	}
}

void client_ap_setup(RunStatus &rs){
	// check if contains rs.get_actor("attacker")["source"] != "internal"
	if(rs.get_actor("client")["source"] != "internal" && (rs.get_actor("client")["source"] != "simulation")){
		throw run_err("only internal actors are supported");
	}

	setup_AP(rs, "access_point");
	setup_STA(rs, "client");

	rs.process_manager.wait_for("client", "EVENT-CONNECTED", seconds(40));
	rs.process_manager.wait_for("access_point", "EAPOL-4WAY-HS-COMPLETED", seconds(40));
	log(LogLevel::INFO, "client is connected");
}

void setup_rogue_ap(RunStatus &rs){
	if(rs.config().at("actors").contains("rogue_ap")){
		copy_file(rs.config_path().parent_path() / "config" / "hostapd-mana.conf",
				rs.run_folder() / "rogue_ap_hostapd_mana.conf");
		set_public_perms(rs.run_folder() / "rogue_ap_hostapd_mana.conf");
		program::start(rs, "rogue_ap");
		rs.process_manager.wait_for("rogue_ap", "AP-ENABLED", seconds(30));
		log(LogLevel::INFO, "Rogue AP up");
	}
};

void client_ap_attacker_setup_enterprise(RunStatus &rs){
	if( (rs.get_actor("attacker")["source"] != "simulation" || rs.get_actor("client")["source"] != "simulation")
	 && (rs.get_actor("attacker")["source"] != "internal" || rs.get_actor("client")["source"] != "internal")){
		throw run_err("only internal actors are supported");
	}

	if(rs.get_actor("access_point")->is_WB()) setup_AP(rs, "access_point");
	setup_STA(rs, "client");

	rs.process_manager.wait_for("client", "EVENT-CONNECTED", seconds(40));
	//if(rs.get_actor("access_point")->is_WB()){
	//    rs.process_manager.wait_for("access_point", "AP-STA-CONNECTED", chrono::seconds(40));
	//} // ony check, not
	log(LogLevel::INFO, "client is connected");
}
}