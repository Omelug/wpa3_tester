#include "attacks/mc_mitm/wifi_util.h"
#include "config/Actor_config.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester{
using namespace std;

void Actor_config::set_mac(const string &mac_address){
	string mac_lower = mac_address;
	ranges::transform(mac_lower, mac_lower.begin(), [](const unsigned char c){ return tolower(c); });
	(*this)[SK::mac] = mac_lower;
}

void Actor_config::setup_actor(const nlohmann::json &config, const ActorPtr &real_actor){
	const bool internal = (*this)[SK::source].value() == "internal";
	const bool external_WB = is_external_WB();
	conn = real_actor->conn;
	if(internal || external_WB){
		// (same if set in config)
		(*this)[SK::driver] = real_actor[SK::driver];
	}
	if(internal){
		(*this)[SK::iface] = real_actor[SK::iface];
		(*this)[SK::radio] = real_actor[SK::radio];
		if(!(*this)[SK::mac].has_value()){
			set_mac(real_actor["mac"]);
		} else{
			set_mac_address(real_actor["mac"]);
		}
	}
	if(external_WB){
		(*this)[SK::whitebox_host] = real_actor[SK::whitebox_host];
		(*this)[SK::whitebox_ip] = real_actor[SK::whitebox_ip];
		(*this)[SK::ssh_user] = real_actor[SK::ssh_user];
		(*this)[SK::ssh_port] = real_actor[SK::ssh_port];
		(*this)[SK::ssh_password] = real_actor[SK::ssh_password];
		(*this)[SK::external_OS] = real_actor[SK::external_OS];
		const auto radio = real_actor[SK::radio].value();
		auto actor_ptr = ActorPtr(shared_from_this());
		conn->setup_iface(radio, actor_ptr, config);
	}

	if(internal) setup_actor_internal(config);
	if(external_WB){ setup_actor_external_whitebox(config, real_actor); }
	if(internal || external_WB){
		auto actor_json = config.at("actors").at((*this)[SK::actor_name].value());
		const bool monitor = (*this)[BK::monitor].value_or(false);
		string monitor_flags;
		if((*this)[BK::active_monitor]) monitor_flags += " active";
		if((*this)[BK::control_monitor]) monitor_flags += " control";
		const bool injection = (*this)[BK::injection].value_or(false);

		int channel = -1;
		if(const auto d = (*this)[SK::channel]) channel = stoi(d.value());
		else if(const auto c = real_actor[SK::channel]) channel = stoi(c.value());
		if(channel != -1) set_channel(channel, (*this)[SK::ht_mode].value_or(""));

		if((monitor || injection) && (*this)[SK::sniff_iface] == nullopt) set_monitor_mode(monitor_flags);
		if(actor_json.contains("sniff_iface")){
			(*this)[SK::sniff_iface] = MONITOR_IFACE_PREFIX + actor_json.at("sniff_iface").get<string>();
			create_sniff_iface();
		}
		(*this)[SK::ssid] = real_actor[SK::ssid];
	}

	if(internal){
		//FIXMe shouod be avaible for external_WB
		if((*this)[BK::AP].value_or(false)){
			//set_managed_mode();
			set_ap_mode();
		}
		if((*this)[BK::managed].value_or(false)){ set_managed_mode(); }
		set_iface_up();
		up_sniff_iface();
	}
}

void Actor_config::setup_actor_internal(const nlohmann::json &config){
	const auto actor_name = (*this)[SK::actor_name].value();
	auto actor_json = config.at("actors").at(actor_name);
	if(actor_json.contains("netns")){
		(*this)[SK::netns] = actor_json.at("netns").get<string>();
		hw_capabilities::create_ns((*this)[SK::netns].value());
	}
	this->cleanup();
}

void Actor_config::setup_actor_external_whitebox(const nlohmann::json &config, const ActorPtr &real_actor){
	auto actor_json = config.at("actors").at((*this)[SK::actor_name].value());
	real_actor->conn->check_req(config, (*this)[SK::actor_name].value());
}
}