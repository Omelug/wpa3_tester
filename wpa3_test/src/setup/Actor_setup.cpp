#include "attacks/two_iface/TwoIfaceInject.h"
#include "config/Actor_Config/Actor_config.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester{
using namespace std;

Channel Actor_config::get_channel() const {
	if(!(*this)[SK::channel].has_value())
		throw config_err("Actor_config: channel not set");

	const int ch_num = stoi(get(SK::channel));

	// Determine band from boolean keys
	auto band = WifiBand::BAND_2_4_or_5; // default

	int count = 0;
	if(get_or(BK::GHz2_4, false)) { band = WifiBand::BAND_2_4; count++; }
	if(get_or(BK::GHz5, false)) { band = WifiBand::BAND_5; count++; }
	if(get_or(BK::GHz6, false)) { band = WifiBand::BAND_6; count++; }

	if(count > 1) throw config_err("Actor_config: Multiple bands set (2_4GHz, 5GHz, 6GHz). Only one allowed.");

	// Validate channel number for band
	const auto valid_2_4 = [](const int c){ return c >= 1 && c <= 14; };
	const auto valid_5 = [](const int c){ return (c >= 36 && c <= 48) || (c >= 52 && c <= 144) || (c >= 149 && c <= 165); };
	const auto valid_6 = [](const int c){ return c >= 1 && c <= 233; };

	if(band == WifiBand::BAND_2_4 && !valid_2_4(ch_num))
		throw config_err("Actor_config: Invalid 2.4GHz channel " + to_string(ch_num));
	if(band == WifiBand::BAND_5 && !valid_5(ch_num))
		throw config_err("Actor_config: Invalid 5GHz channel " + to_string(ch_num));
	if(band == WifiBand::BAND_6 && !valid_6(ch_num))
		throw config_err("Actor_config: Invalid 6GHz channel " + to_string(ch_num));

	// For BAND_2_4_or_5, infer from channel number
	if(band == WifiBand::BAND_2_4_or_5){
		if(valid_2_4(ch_num))      band = WifiBand::BAND_2_4;
		else if(valid_5(ch_num))   band = WifiBand::BAND_5;
		else throw config_err("Actor_config: Channel " + to_string(ch_num) + " invalid for 2.4GHz or 5GHz");
	}

	return Channel{ch_num, band, (*this)[SK::ht_mode]};
}

// Only simulation/internal,external have specific
void Actor_config::setup_actor(const nlohmann::json &config, const ActorPtr &real_actor){
	conn = real_actor->conn;

	set(SK::driver_name, real_actor[SK::driver_name]);
	set(SK::driver_hash, real_actor[SK::driver_hash]);
	set(SK::module_hash, real_actor[SK::module_hash]);

	set(SK::iface, real_actor[SK::iface]);
	set(SK::radio, real_actor[SK::radio]);

	set(SK::ht_mode, real_actor[SK::ht_mode]);
	set(SK::ssid, real_actor[SK::ssid]);

	if((*this)[SK::mac].has_value()){
		// setup force set mac address
		set_mac_address(get(SK::mac));
	}else{
		//just get mac from iface
		set(SK::mac, real_actor.get(SK::mac));
	}

	if(!(*this)[SK::permanent_mac].has_value()){
		const auto perm = hw_capabilities::get_permanent_mac(get(SK::iface), (*this)[SK::netns]);
		if(!perm.empty()) set(SK::permanent_mac, perm);
	}

	if(auto actor_json = config.at("actors").at(get(SK::actor_name)); actor_json.contains("netns")){
		set(SK::netns, actor_json.at("netns").get<string>());
		hw_capabilities::create_ns(get(SK::netns));
	}
	cleanup();

	const auto actor_json = config.at("actors").at(get(SK::actor_name));
	int channel_num = -1;
	if(const auto d = (*this)[SK::channel]) channel_num = stoi(d.value());
	else if(const auto &c = real_actor[SK::channel]) channel_num = stoi(c.value());

	// Set sniff_iface key early so monitor check below knows a VIF will handle capturing
	if(actor_json.contains("sniff_iface"))
		set(SK::sniff_iface, MONITOR_IFACE_PREFIX + actor_json.at("sniff_iface").get<string>());

	if(monitor_needed() && !(*this)[SK::sniff_iface].has_value()) set_monitor_mode();
	if(get_or(BK::injection_selftest, false)){
		const ActorPtr self(shared_from_this());
		if(!TwoIfaceInject::run_check(self, self, run_on_miss, "injection"))
			log(LogLevel::INFO, "Get from cache");
	}

	if(get_or(BK::AP,false)) set_ap_mode();
	if(get_or(BK::managed, false)) set_managed_mode();
	set_iface_up();

	// only in monitor mode is possible set channel everytime (should be set in programs in AP/managed mode)
	if(channel_num != -1 && monitor_needed())
		set_channel(Channel{channel_num, get_channel().band, (*this)[SK::ht_mode]});

	if((*this)[SK::sniff_iface].has_value()) create_sniff_iface();
	up_sniff_iface();
	set_iface_up();
}
}
