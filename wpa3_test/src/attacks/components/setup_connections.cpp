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

void client_ap_setup(RunStatus &rs, const bool check_way_eapol){
	// check if contains rs.getactor("attacker").get(SK::source) != "internal"
	if(rs.get_actor("access_point")->is_WB()) setup_AP(rs, "access_point");

	if(rs.get_actor("client")->is_WB()){
		setup_STA(rs, "client");
		rs.process_manager.wait_for("client", "EVENT-CONNECTED", seconds(40));
	} else if(rs.get_actor("client").is(SK::source, "external") &&
	          rs.get_actor("access_point").is(SK::source, "internal")){
		log(LogLevel::INFO, "Connect external client to AP — ssid='{}' password='{}'",
		    hostapd::get_ssid(rs, "access_point"),
		    hostapd::get_password(rs, "access_point"));

		string matched_line;
		if(check_way_eapol){
			rs.process_manager.wait_for("access_point", "EAPOL-4WAY-HS-COMPLETED", seconds(120), true, &matched_line);
		} else{
			rs.process_manager.wait_for("access_point", "AP-STA-CONNECTED", seconds(120), true, &matched_line);
		}

		smatch m;
		if(regex_search(matched_line, m, regex(R"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})"))){
			const Tins::HWAddress<6> mac(m[0].str());
			rs.get_actor("client")->set(SK::mac, mac);
			rs.get_actor("client")->set(SK::permanent_mac, mac);
		} else{
			log(LogLevel::WARNING, "AP-STA-CONNECTED: could not parse MAC from '{}'", matched_line);
		}
		log(LogLevel::INFO, "client connected: {}", matched_line);
		return;
	}

	if(rs.get_actor("access_point").get(SK::source) != "external"){
		if(check_way_eapol){
			rs.process_manager.wait_for("access_point", "EAPOL-4WAY-HS-COMPLETED", seconds(40));
		} else{
			rs.process_manager.wait_for("access_point", "AP-STA-CONNECTED", seconds(10));
		}
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
