#include "config/Actor_Config/Actor_config.h"
#include "logger/error_log.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester {

Channel Actor_config::get_channel() const {
	if(!(*this)[SK::channel].has_value()) throw config_err("Actor_config: channel not set");

	const int ch_num = stoi(get(SK::channel));

	const bool is_valid_2_4 = ch_num >= 1 && ch_num <= 14;
	const bool is_valid_5 =
			(ch_num >= 36 && ch_num <= 48) || (ch_num >= 52 && ch_num <= 144) || (ch_num >= 149 && ch_num <= 165);
	const bool is_valid_6 = ch_num >= 1 && ch_num <= 233;

	const bool conf_2_4 = get_or(BK::GHz2_4, false);
	const bool conf_5 = get_or(BK::GHz5, false);
	const bool conf_6 = get_or(BK::GHz6, false);

	const bool matches_2_4 = is_valid_2_4 && conf_2_4;
	const bool matches_5 = is_valid_5 && conf_5;
	const bool matches_6 = is_valid_6 && conf_6;

	const int match_count = matches_2_4 + matches_5 + matches_6;

	if(match_count == 0) {
		throw config_err("Actor_config: Channel {} is not valid for any enabled band (2.4GHz: {}, 5GHz: {}, 6GHz: {})",
				ch_num, conf_2_4, conf_5, conf_6);
	}

	if(match_count > 1) {
		throw config_err(
				"Actor_config: Ambiguous channel {} - matches multiple enabled bands. Only one band can be active.",
				ch_num);
	}

	const WifiBand band = matches_6 ? WifiBand::BAND_6
			: matches_2_4			? WifiBand::BAND_2_4
			: matches_5				? WifiBand::BAND_5
									: WifiBand::BAND_2_4_or_5;

	return Channel{ .ch_num = static_cast<uint8_t>(ch_num), .band = band, .ht_mode = (*this)[SK::ht_mode] };
}

void Actor_config::real_actor_setup_base_keys(const ActorPtr &real_actor) {
	set(real_actor,{
	{
		SK::driver_name,
		SK::driver_hash,
		SK::module_hash,
		SK::iface,
		SK::radio,

		SK::whitebox_host,
		SK::whitebox_ip,
		SK::ssh_user,
		SK::ssh_port,
		SK::ssh_password,
		SK::external_OS
	},{
		// this is only support not flag to set up
		BK::w80211n,
		BK::w80211ac,
		BK::w80211ax,
		BK::beacon_prot,
		BK::PBAC,
		BK::CSA,
		BK::OCV,
		BK::MFP,
		BK::WPA_PSK,
		BK::WPA3_SAE
	}
});
	if(!(*this)[SK::netns].has_value()) set(real_actor, SK::netns);
	if(!(*this)[SK::channel].has_value()) set(real_actor, SK::channel);
	if(!(*this)[SK::ssid].has_value()) set(real_actor, SK::ssid);

	if(get_or(BK::active_monitor, false)) set(real_actor, BK::active_monitor);
	if(get_or(BK::control_monitor, false)) set(real_actor, BK::control_monitor);
	if(get_or(BK::GHz2_4, false)) set(real_actor, BK::GHz2_4);
	if(get_or(BK::GHz5, false)) set(real_actor, BK::GHz5);
	if(get_or(BK::GHz6, false)) set(real_actor, BK::GHz6);

	if((*this)[SK::mac].has_value()) {
		set_mac_address(get(SK::mac)); // setup mac address with macchanger
	} else {
		set(real_actor, SK::mac);
	}
	set(real_actor, SK::permanent_mac);


}
// Only simulation/internal,external have specific
void Actor_config::setup_actor(const nlohmann::json &/*config*/, const ActorPtr &real_actor, RunStatus *) {
	conn = real_actor->conn;
	real_actor_setup_base_keys(real_actor);
	if((*this)[SK::netns]) hw_capabilities::create_netns(get(SK::netns));
	cleanup();

	const bool no_sniff_iface = !(*this)[BK::sniff_iface].has_value() ||
			((*this)[BK::sniff_iface].has_value() && !(*this)[BK::sniff_iface].value());
	const auto base_mon_iface = monitor_needed() && no_sniff_iface;

	if(base_mon_iface) set_monitor_mode();
	if(get_or(BK::AP, false)) set_ap_mode(); //FIXME not implemented yet
	if(get_or(BK::managed, false)) set_managed_mode();

	/* FIXME this will broke -> cant be set iun requirements like other injection tests? Or needed injection_selftest at all?
	if(get_or(BK::injection_selftest, false)) {
		const ActorPtr self(shared_from_this());
		const auto cb = get_global_config().value("use_two_iface_cache", true) ? run_on_miss : force_run;
		if(!TwoIfaceInject::run_check(self, self, cb, "injection")) log(LogLevel::INFO, "Get from cache");
	}*/

	set_iface_up();
	if((*this)[SK::channel].has_value() && base_mon_iface) set_channel(get_channel());

	if((*this)[BK::sniff_iface]) {
		create_sniff_iface();
		up_sniff_iface();
	}
	set_iface_up();
}
}
