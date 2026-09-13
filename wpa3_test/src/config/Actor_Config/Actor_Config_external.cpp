#include "config/Actor_Config/Actor_Config_external.h"
#include "config/RunStatus.h"
#include "ex_program/external_actors/ExternalConn.h"

namespace wpa3_tester {
using namespace std;

void Actor_Config_external::setup_actor(const nlohmann::json &config, const ActorPtr &real_actor, RunStatus *rs) {
	if((*this)[SK::mac].has_value()) {
		// setup force set mac address
		set_mac_address(get(SK::mac));
	} else {
		//just get mac from iface
		set(SK::mac, real_actor.get(SK::mac));
	}

	// ---------- other setup only for whitebox
	if(!is_external_WB()) return;

	conn = real_actor->conn;
	set(real_actor,
			{ { SK::ssid,
					  SK::driver_name,
					  SK::driver_hash,
					  SK::module_hash,
					  SK::whitebox_host,
					  SK::whitebox_ip,
					  SK::ssh_user,
					  SK::ssh_port,
					  SK::ssh_password,
					  SK::external_OS },
					{ BK::w80211n,
							BK::w80211ac,
							BK::w80211ax,
							BK::beacon_prot,
							BK::CSA,
							BK::OCV,
							BK::MFP,
							BK::WPA_PSK,
							BK::WPA3_SAE } });

	if(get_or(BK::active_monitor, false)) set(real_actor, BK::active_monitor);
	if(get_or(BK::control_monitor, false)) set(real_actor, BK::control_monitor);
	if(get_or(BK::GHz2_4, false)) set(real_actor, BK::GHz2_4);
	if(get_or(BK::GHz5, false)) set(real_actor, BK::GHz5);
	if(get_or(BK::GHz6, false)) set(real_actor, BK::GHz6);

	auto actor_ptr = ActorPtr(shared_from_this());
	conn->setup_iface(real_actor->get(SK::radio), actor_ptr, config);
	real_actor->conn->check_req(config, get(SK::actor_name));

	const auto actor_json = config.at("actors").at(get(SK::actor_name));
	int channel_num = -1;
	if(const auto d = (*this)[SK::channel]) {
		channel_num = stoi(d.value());
	} else if(const auto &c = real_actor[SK::channel]) {
		channel_num = stoi(c.value());
	}

	if(monitor_needed() && (*this)[BK::sniff_iface]) set_monitor_mode();

	if(channel_num != -1) {
		//set_iface_up();
		set_channel(get_channel());
		//set_iface_down();
	}

	//FIXME external, before channel switch?
	if(actor_json.contains("sniff_iface")) {
		set(BK::sniff_iface, actor_json.at("sniff_iface").get<bool>());
		create_sniff_iface();
	}
	conn->exec("ip link set " + get(SK::iface) + " up");

	if(rs) conn->get_router_info(*rs, get(SK::actor_name));
}
}
