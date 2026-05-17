#include "attacks/mc_mitm/wifi_util.h"
#include "config/Actor_config.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester{
using namespace std;

/*void Actor_config::set_mac(const string &mac_address){
	string mac_lower = mac_address;
	ranges::transform(mac_lower, mac_lower.begin(), [](const unsigned char c){ return tolower(c); });
	set(SK::mac, mac_lower);
}

void Actor_config::set_permanent_mac(const string &mac_address){
	string mac_lower = mac_address;
	ranges::transform(mac_lower, mac_lower.begin(), [](const unsigned char c){ return tolower(c); });
	set(SK::permanent_mac, mac_lower);
}*/

Channel Actor_config::get_channel() const {
	if(!(*this)[SK::channel].has_value())
		throw config_err("Actor_config: channel not set");

	const int ch_num = stoi(get(SK::channel));

	// Determine band from boolean keys
	const bool has_2_4 = (*this)[BK::GHz2_4].value_or(false);
	const bool has_5 = (*this)[BK::GHz5].value_or(false);
	const bool has_6 = (*this)[BK::GHz6].value_or(false);

	WifiBand band = WifiBand::BAND_2_4_or_5; // default
	int count = 0;

	if(has_2_4) { band = WifiBand::BAND_2_4; count++; }
	if(has_5) { band = WifiBand::BAND_5; count++; }
	if(has_6) { band = WifiBand::BAND_6; count++; }

	if(count > 1)
		throw config_err("Actor_config: Multiple bands set (2_4GHz, 5GHz, 6GHz). Only one allowed.");

	// Validate channel number for band
	const auto valid_2_4 = [](int c){ return c >= 1 && c <= 14; };
	const auto valid_5 = [](int c){ return (c >= 36 && c <= 48) || (c >= 52 && c <= 144) || (c >= 149 && c <= 165); };
	const auto valid_6 = [](int c){ return c >= 1 && c <= 233; };

	if(band == WifiBand::BAND_2_4 && !valid_2_4(ch_num))
		throw config_err("Actor_config: Invalid 2.4GHz channel " + to_string(ch_num));
	if(band == WifiBand::BAND_5 && !valid_5(ch_num))
		throw config_err("Actor_config: Invalid 5GHz channel " + to_string(ch_num));
	if(band == WifiBand::BAND_6 && !valid_6(ch_num))
		throw config_err("Actor_config: Invalid 6GHz channel " + to_string(ch_num));

	// For BAND_2_4_or_5, try to infer
	if(band == WifiBand::BAND_2_4_or_5){
		if(valid_2_4(ch_num)) band = WifiBand::BAND_2_4;
		else if(valid_5(ch_num)) band = WifiBand::BAND_5;
		else throw config_err("Actor_config: Channel " + to_string(ch_num) + " invalid for 2.4GHz or 5GHz");
	}

	return Channel{ch_num, band};
}

void Actor_config::setup_actor(const nlohmann::json &config, const ActorPtr &real_actor){
	const bool internal = get(SK::source) == "internal" ||
	                      get(SK::source) == "simulation";
	const bool external_WB = is_external_WB();
	conn = real_actor->conn;
	if(internal || external_WB){
		// (same if set in config)
		set(SK::driver_name, real_actor[SK::driver_name]);
	}
	if(internal){
		set(SK::iface, real_actor[SK::iface]);
		set(SK::radio, real_actor[SK::radio]);
		if(!(*this)[SK::mac].has_value()){
			set_mac(real_actor["mac"]);
		} else{
			set_mac_address(real_actor["mac"]);
		}
		if(!(*this)[SK::permanent_mac].has_value()){
			const auto perm = hw_capabilities::get_permanent_mac(get(SK::iface), (*this)[SK::netns]);
			if(!perm.empty()) set_permanent_mac(perm);
		}
	}
	if(external_WB){
		set(SK::whitebox_host, real_actor[SK::whitebox_host]);
		set(SK::whitebox_ip, real_actor[SK::whitebox_ip]);
		set(SK::ssh_user, real_actor[SK::ssh_user]);
		set(SK::ssh_port, real_actor[SK::ssh_port]);
		set(SK::ssh_password, real_actor[SK::ssh_password]);
		set(SK::external_OS, real_actor[SK::external_OS]);
		const auto radio = real_actor[SK::radio].value();
		auto actor_ptr = ActorPtr(shared_from_this());
		conn->setup_iface(radio, actor_ptr, config);
	}

	if(internal) setup_actor_internal(config);
	if(external_WB){ setup_actor_external_whitebox(config, real_actor); }
	if(internal || external_WB){
		auto actor_json = config.at("actors").at(get(SK::actor_name));
		const bool monitor = (*this)[BK::monitor].value_or(false);
		const bool injection = (*this)[BK::injection].value_or(false);

		int channel_num = -1;
		if(const auto d = (*this)[SK::channel]) channel_num = stoi(d.value());
		else if(const auto c = real_actor[SK::channel]) channel_num = stoi(c.value());
		if(channel_num != -1) set_channel(Channel{channel_num}, (*this)[SK::ht_mode].value_or(""));

		if((monitor || injection) && (*this)[SK::sniff_iface] == nullopt) set_monitor_mode();
		if(actor_json.contains("sniff_iface")){
			set(SK::sniff_iface, MONITOR_IFACE_PREFIX + actor_json.at("sniff_iface").get<string>());
			create_sniff_iface();
		}
		set(SK::ssid, real_actor[SK::ssid]);
	}

	if(internal){
		//FIXMe should be available for external_WB
		if((*this)[BK::AP].value_or(false)){
			set_ap_mode();
		}
		if((*this)[BK::managed].value_or(false)){ set_managed_mode(); }
		set_iface_up();
		up_sniff_iface();
	}
}

void Actor_config::setup_actor_internal(const nlohmann::json &config){
	const auto actor_name = get(SK::actor_name);
	if(auto actor_json = config.at("actors").at(actor_name); actor_json.contains("netns")){
		set(SK::netns, actor_json.at("netns").get<string>());
		hw_capabilities::create_ns(get(SK::netns));
	}
	cleanup();
}

void Actor_config::setup_actor_external_whitebox(const nlohmann::json &config, const ActorPtr &real_actor) const{
	real_actor->conn->check_req(config, get(SK::actor_name));
}
}