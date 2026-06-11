#include <map>
#include <set>
#include <variant>
#include "attacks/scanner/external_info.h"
#include "attacks/components/sniffer_helper.h"
#include "config/RunStatus.h"
#include "scan/active/scan_STA.h"

using namespace std;
using namespace Tins;
using namespace chrono;

namespace wpa3_tester::external_info{

void run_attack(RunStatus &rs){
	rs.start_observers();
	const auto &att_cfg = rs.config().at("attack_config");
	const auto scanner  = rs.get_actor("scanner");

	const int timeout_sec = att_cfg.at("timeout_sec").get<int>();
	const int actor_limit = att_cfg.value("actor_limit",  0);   // 0 = unlimited

	map<string, Actor_Config_external> ap_map;  // bssid → full info
	set<string> sta_macs;

	components::poll_sniffer_pdu<monostate>(
		[&](PDU &pdu) -> optional<monostate> {
			// beacon → full AP info
			if(const auto *beacon = pdu.find_pdu<Dot11Beacon>()){
				const string bssid = beacon->addr3().to_string();
				if(!ap_map.contains(bssid)){
					Actor_Config_external cfg;
					scan::fill_actor_caps_from_beacon(pdu, cfg);
					ap_map[bssid] = std::move(cfg);
					log(LogLevel::DEBUG, "Found AP: {}", bssid);
					if(actor_limit > 0 && static_cast<int>(ap_map.size()) >= actor_limit)
						return monostate{};
				}
			}

			// probe request (subtype 4) transmitter = STA
			if(const auto *mgmt = pdu.find_pdu<Dot11ManagementFrame>(); mgmt && mgmt->subtype() == 4){
				const string mac = mgmt->addr2().to_string();
				if(mac != "ff:ff:ff:ff:ff:ff") sta_macs.insert(mac);
			}

			// data frame transmitter that is not a known AP = STA (mac only, like Scan_STA)
			if(const auto *data = pdu.find_pdu<Dot11Data>()){
				const string mac = data->addr2().to_string();
				if(mac != "ff:ff:ff:ff:ff:ff" && !ap_map.count(mac)) sta_macs.insert(mac);
			}

			return nullopt;
		},
		scanner["iface"],
		"type mgt subtype beacon or type mgt subtype probe-req or type data",
		seconds(timeout_sec)
	);

	// TODO: save APs and STAs to database
	nlohmann::json aps = nlohmann::json::array();
	for(const auto &cfg: ap_map | views::values) aps.push_back(cfg.to_json());

	nlohmann::json stas = nlohmann::json::array();
	for(const auto &mac: sta_macs) stas.push_back(mac);

	rs.save_result({
		{"ap_count",  static_cast<int>(ap_map.size())},
		{"sta_count", static_cast<int>(sta_macs.size())},
		{"aps",       aps},
		{"stations",  stas},
	});
}

}
