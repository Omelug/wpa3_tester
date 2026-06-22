#include "config/RunStatus.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "ex_program/hostapd/hostapd_helper.h"
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

void stop_AP(RunStatus &rs, const string &actor_name){
	const auto &actor = rs.get_actor(actor_name);
	assert(actor->is_WB());
	if(actor->is_external_WB()){
		actor->conn->exec("wifi down");
	} else{
		rs.process_manager.stop(actor_name);
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
	// check if contains rs.getactor("attacker").get(SK::source) != "internal"
	if(rs.get_actor("access_point")->is_WB()) setup_AP(rs, "access_point");

	if(rs.get_actor("client")->is_WB()){
		setup_STA(rs, "client");
	} else{
		string answer;
		cout << "Is device connected to AP '" << hostapd::get_ssid(rs, "access_point") <<
				"'? Connect it and press enter." << flush;
		getline(cin, answer);
		return;
	}

	rs.process_manager.wait_for("client", "EVENT-CONNECTED", seconds(40));

	if(rs.get_actor("access_point").get(SK::source) != "external"){
		rs.process_manager.wait_for("access_point", "EAPOL-4WAY-HS-COMPLETED", seconds(40));
	}
	log(LogLevel::INFO, "client is connected");
}

void setup_rogue_ap(RunStatus &rs){
	if(rs.config().at("actors").contains("rogue_ap")){
		const auto conf = rs.config_path().parent_path() / "config" / "hostapd-mana.conf";
		if(exists(conf)){
			copy_f(conf, rs.run_folder() / "rogue_ap_hostapd_mana.conf");
		}
		program::start(rs, "rogue_ap");
		rs.process_manager.wait_for("rogue_ap", "AP-ENABLED", seconds(30));
		log(LogLevel::INFO, "Rogue AP up");
	}
};

void client_ap_attacker_setup_enterprise(RunStatus &rs){
	if((rs.get_actor("attacker").get(SK::source) != "simulation" || rs.get_actor("client").get(SK::source) !=
		"simulation") && (rs.get_actor("attacker").get(SK::source) != "internal" || rs.get_actor("client").
		get(SK::source) != "internal")){
		throw run_err("only internal actors are supported");
	}

	if(rs.get_actor("access_point")->is_WB()) setup_AP(rs, "access_point");
	setup_STA(rs, "client");

	rs.process_manager.wait_for("client", "EVENT-CONNECTED", seconds(40));
	log(LogLevel::INFO, "client is connected");
}
}
