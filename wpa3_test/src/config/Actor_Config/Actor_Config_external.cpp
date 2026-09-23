#include "config/Actor_Config/Actor_Config_external.h"
#include "config/RunStatus.h"
#include "ex_program/external_actors/ExternalConn.h"

namespace wpa3_tester {
using namespace std;

void Actor_Config_external::setup_actor(const nlohmann::json &config, const ActorPtr &real_actor, RunStatus *rs) {
	conn = real_actor->conn;

	real_actor_setup_base_keys(real_actor);

	if(!is_external_WB()) return;

	auto actor_ptr = ActorPtr(shared_from_this());
	conn->setup_iface(real_actor->get(SK::radio), actor_ptr, config);
	real_actor->conn->check_req(config, get(SK::actor_name));

	const bool no_sniff_iface = !(*this)[BK::sniff_iface].has_value() ||
			((*this)[BK::sniff_iface].has_value() && !(*this)[BK::sniff_iface].value());
	const auto base_mon_iface = monitor_needed() && no_sniff_iface;

	//not used for openwrt setup (setup with setup/program_config in setup_iface)
	//if(base_mon_iface) set_monitor_mode();
	//if(get_or(BK::AP, false)) set_ap_mode(); //FIXME not implemented yet
	//if(get_or(BK::managed, false)) set_managed_mode();

	set_iface_up();
	if((*this)[SK::channel].has_value() && base_mon_iface) set_channel(get_channel());

	if((*this)[BK::sniff_iface]) {
		create_sniff_iface();
		up_sniff_iface();
	}
	set_iface_up();

	if(rs) conn->get_router_info(*rs, get(SK::actor_name));
}
}
