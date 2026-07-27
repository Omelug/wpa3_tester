#include "attacks/two_iface/TwoIfaceInject.h"
#include "config/Actor_Config/Actor_config.h"
#include "config/global_config.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester{
using string = std::string;

Channel Actor_config::get_channel() const{
	if(!(*this)[SK::channel].has_value()) throw config_err("Actor_config: channel not set");

	const int ch_num = stoi(get(SK::channel));

	const bool is_valid_2_4 = (ch_num >= 1 && ch_num <= 14);
	const bool is_valid_5   = (ch_num >= 36 && ch_num <= 48) ||
							  (ch_num >= 52 && ch_num <= 144) ||
							  (ch_num >= 149 && ch_num <= 165);
	const bool is_valid_6   = (ch_num >= 1 && ch_num <= 233);

	const bool conf_2_4 = get_or(BK::GHz2_4, false);
	const bool conf_5   = get_or(BK::GHz5, false);
	const bool conf_6   = get_or(BK::GHz6, false);

	const bool matches_2_4 = is_valid_2_4 && conf_2_4;
	const bool matches_5   = is_valid_5 && conf_5;
	const bool matches_6   = is_valid_6 && conf_6;

	const int match_count = matches_2_4 + matches_5 + matches_6;

	if (match_count == 0) {
		throw config_err("Actor_config: Channel {} is not valid for any enabled band (2.4GHz: {}, 5GHz: {}, 6GHz: {})",
						 ch_num, conf_2_4, conf_5, conf_6);
	}

	if (match_count > 1) {
		throw config_err("Actor_config: Ambiguous channel {} - matches multiple enabled bands. Only one band can be active.", ch_num);
	}

	const WifiBand band = matches_6   ? WifiBand::BAND_6 :
						  matches_2_4 ? WifiBand::BAND_2_4 :
						  matches_5   ? WifiBand::BAND_5 :
										WifiBand::BAND_2_4_or_5;

	return Channel{
		.ch_num  = static_cast<uint8_t>(ch_num),
		.band    = band,
		.ht_mode = (*this)[SK::ht_mode]
	};
}

// Only simulation/internal,external have specific
void Actor_config::setup_actor(const nlohmann::json &config, const ActorPtr &real_actor){
	conn = real_actor->conn;

	set(real_actor, {
		{
			SK::driver_name,SK::driver_hash,SK::module_hash,
			SK::iface, SK::radio,
			SK::ht_mode, SK::ssid
		},{
			BK::w80211n, BK::w80211ac, BK::w80211ax, BK::beacon_prot,
			BK::CSA, BK::OCV, BK::MFP, BK::WPA_PSK, BK::WPA3_SAE
		}
	});

	if(get_or(BK::GHz2_4, false)) set(real_actor, BK::GHz2_4);
	if(get_or(BK::GHz5, false)) set(real_actor, BK::GHz5);
	if(get_or(BK::GHz6, false)) set(real_actor, BK::GHz6);

	if((*this)[SK::mac].has_value()){
		// setup force set mac address
		set_mac_address(get(SK::mac));
	} else{
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
	uint8_t channel_num = 0;
	if(const auto d = (*this)[SK::channel]) channel_num = stoi(d.value());
	else if(const auto &c = real_actor[SK::channel]) channel_num = stoi(c.value());

	// Set sniff_iface key early so monitor check below knows a VIF will handle capturing
	if(actor_json.contains("sniff_iface")) set(SK::sniff_iface,
												MONITOR_IFACE_PREFIX + actor_json.at("sniff_iface").get<string>());

	if(monitor_needed() && !(*this)[SK::sniff_iface].has_value()) set_monitor_mode();
	if(get_or(BK::injection_selftest, false)){
		const ActorPtr self(shared_from_this());
		const auto cb = get_global_config().value("use_two_iface_cache", true) ? run_on_miss : force_run;
		if(!TwoIfaceInject::run_check(self, self, cb, "injection")) log(LogLevel::INFO, "Get from cache");
	}

	if(get_or(BK::AP, false)) set_ap_mode();
	if(get_or(BK::managed, false)) set_managed_mode();
	set_iface_up();

	// only in monitor mode is possible set channel everytime (should be set in programs in AP/managed mode)
	if(channel_num != 0 && monitor_needed()) set_channel(
		Channel{channel_num, get_channel().band, (*this)[SK::ht_mode]});

	if((*this)[SK::sniff_iface].has_value()) create_sniff_iface();
	up_sniff_iface();
	set_iface_up();
}
}
