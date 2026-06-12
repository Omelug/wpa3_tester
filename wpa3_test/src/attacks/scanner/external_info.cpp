#include "attacks/scanner/external_info.h"
#include <map>
#include <variant>
#include "attacks/components/sniffer_helper.h"
#include "config/RunStatus.h"
#include "scan/active/scan_STA.h"

using namespace std;
using namespace Tins;
using namespace chrono;

namespace wpa3_tester::external_info{

static void try_add_sta(ApInfoMap &ap_map, StaInfoMap &sta_map,
						const HWAddress<6> &bssid, const HWAddress<6> &mac){
	if(mac == HWAddress<6>("ff:ff:ff:ff:ff:ff") || mac == bssid) return;
	ap_map[bssid].stations.insert(mac);
	if(!sta_map.contains(mac)){
		Actor_Config_external cfg;
		cfg.set(SK::mac, mac.to_string());
		sta_map.emplace(mac, std::move(cfg));
	}
}

static bool parse_frame(PDU &pdu, ApInfoMap &ap_map, StaInfoMap &sta_map){
	if(const auto *beacon = pdu.find_pdu<Dot11Beacon>()){
		const HWAddress<6> bssid = beacon->addr3();
		if(!ap_map.contains(bssid)){
			scan::fill_actor_caps_from_beacon(pdu, ap_map[bssid].cfg);
			log(LogLevel::DEBUG, "Found AP: {}", bssid);
			return true;
		}
		return false;
	}

	// assoc-req: fill STA caps independently of AP association
	if(const auto *mgmt = pdu.find_pdu<Dot11ManagementFrame>()){
		if(mgmt->subtype() == 0){
			const HWAddress<6> bssid = mgmt->addr1();
			const HWAddress<6> sta   = mgmt->addr2();
			scan::fill_actor_caps_from_assoc_req(pdu, sta_map[sta]);
			if(ap_map.contains(bssid)) ap_map[bssid].stations.insert(sta);
			log(LogLevel::DEBUG, "STA caps from assoc-req: {}", sta);
		}
		return false;
	}

	// data frames: addr2==BSSID → STA is addr1; addr1==BSSID → STA is addr2
	if(const auto *data = pdu.find_pdu<Dot11Data>()){
		const HWAddress<6> a1 = data->addr1();
		const HWAddress<6> a2 = data->addr2();
		if(ap_map.contains(a2)) try_add_sta(ap_map, sta_map, a2, a1);
		else if(ap_map.contains(a1)) try_add_sta(ap_map, sta_map, a1, a2);
	}
	return false;
}

void run_attack(RunStatus &rs){
	rs.start_observers();
	const auto &att_cfg = rs.config().at("attack_config");
	const auto scanner  = rs.get_actor("scanner");

	const int timeout_sec = att_cfg.at("timeout_sec").get<int>();
	const int actor_limit = att_cfg.value("actor_limit", 0);

	ApInfoMap ap_map;
	StaInfoMap sta_map;

	components::poll_sniffer_pdu<monostate>(
		[&](PDU &pdu) -> optional<monostate> {
			const bool new_ap = parse_frame(pdu, ap_map, sta_map);
			if(new_ap && actor_limit > 0 && static_cast<int>(ap_map.size()) >= actor_limit)
				return monostate{};
			return nullopt;
		},
		scanner.get(SK::iface),
		"type mgt subtype beacon or type mgt subtype assoc-req or type data",
		seconds(timeout_sec)
	);

	nlohmann::json aps = nlohmann::json::array();
	for(const auto &entry: ap_map | views::values){
		auto ap_json = entry.cfg.to_json();
		nlohmann::json sta_list = nlohmann::json::array();
		for(const auto &mac: entry.stations) sta_list.push_back(mac.to_string());
		ap_json["sta_count"] = static_cast<int>(entry.stations.size());
		ap_json["stations"]  = sta_list;
		aps.push_back(ap_json);
	}

	nlohmann::json stas = nlohmann::json::array();
	for(const auto &sta_cfg: sta_map | views::values) stas.push_back(sta_cfg.to_json());

	rs.save_result({
		//{"ap_count",  static_cast<int>(ap_map.size())},
		//{"sta_count", static_cast<int>(sta_map.size())},
		{"aps",       aps},
		{"stations",  stas},
	});
}

}
