#include "config/Actor_Config/Actor_Config_external.h"
#include "ex_program/external_actors/ExternalConn.h"

namespace wpa3_tester{
using namespace std;

void Actor_Config_external::setup_actor(const nlohmann::json &config, const ActorPtr &real_actor){
	set(SK::ssid, real_actor[SK::ssid]);

	if((*this)[SK::mac].has_value()){
		// setup force set mac address
		set_mac_address(get(SK::mac));
	} else{
		//just get mac from iface
		set(SK::mac, real_actor.get(SK::mac));
	}

	// other setup only for whitebox
	if(!is_external_WB()) return;
	conn = real_actor->conn;

	set(SK::driver_name, real_actor[SK::driver_name]);
	set(SK::driver_hash, real_actor[SK::driver_hash]);
	set(SK::module_hash, real_actor[SK::module_hash]);

	set(SK::whitebox_host, real_actor[SK::whitebox_host]);
	set(SK::whitebox_ip, real_actor[SK::whitebox_ip]);
	set(SK::ssh_user, real_actor[SK::ssh_user]);
	set(SK::ssh_port, real_actor[SK::ssh_port]);
	set(SK::ssh_password, real_actor[SK::ssh_password]);
	set(SK::external_OS, real_actor[SK::external_OS]);

	auto actor_ptr = ActorPtr(shared_from_this());
	conn->setup_iface(real_actor->get(SK::radio), actor_ptr, config);
	real_actor->conn->check_req(config, get(SK::actor_name));

	const auto actor_json = config.at("actors").at(get(SK::actor_name));
	int channel_num = -1;
	if(const auto d = (*this)[SK::channel]){
		channel_num = stoi(d.value());
	}else if(const auto &c = real_actor[SK::channel]){
		channel_num = stoi(c.value());
	}

	if(monitor_needed() && !(*this)[SK::sniff_iface].has_value()) set_monitor_mode();

	if(channel_num != -1){
		//set_iface_up();
		set_channel(get_channel());
		//set_iface_down();
	}

	//FIXME before channel switch?>
	if(actor_json.contains("sniff_iface")){
		set(SK::sniff_iface, MONITOR_IFACE_PREFIX + actor_json.at("sniff_iface").get<string>());
		create_sniff_iface();
	}
	conn->exec("ip link set " + get(SK::iface) + " up");
}
}
