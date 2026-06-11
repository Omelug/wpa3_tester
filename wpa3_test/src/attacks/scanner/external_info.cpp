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

struct ApEntry {
	Actor_Config_external cfg;
	set<string> stations;
};

static void try_add_sta(map<string, ApEntry> &ap_map, const string &bssid, const string &mac){
	if(mac == "ff:ff:ff:ff:ff:ff" || mac == bssid) return;
	ap_map[bssid].stations.insert(mac);
}

static bool parse_frame(PDU &pdu, map<string, ApEntry> &ap_map){
	if(const auto *beacon = pdu.find_pdu<Dot11Beacon>()){
		const string bssid = beacon->addr3().to_string();
		if(!ap_map.contains(bssid)){
			scan::fill_actor_caps_from_beacon(pdu, ap_map[bssid].cfg);
			log(LogLevel::DEBUG, "Found AP: {}", bssid);
			return true;
		}
		return false;
	}

	// data frames: addr2==BSSID → STA is addr1; addr1==BSSID → STA is addr2
	if(const auto *data = pdu.find_pdu<Dot11Data>()){
		const string a1 = data->addr1().to_string();
		const string a2 = data->addr2().to_string();
		if(ap_map.contains(a2)) try_add_sta(ap_map, a2, a1);
		else if(ap_map.contains(a1)) try_add_sta(ap_map, a1, a2);
	}

	return false;
}

void run_attack(RunStatus &rs){
	rs.start_observers();
	const auto &att_cfg = rs.config().at("attack_config");
	const auto scanner  = rs.get_actor("scanner");

	const int timeout_sec = att_cfg.at("timeout_sec").get<int>();
	const int actor_limit = att_cfg.value("actor_limit", 0);

	map<string, ApEntry> ap_map;

	components::poll_sniffer_pdu<monostate>(
		[&](PDU &pdu) -> optional<monostate> {
			const bool new_ap = parse_frame(pdu, ap_map);
			if(new_ap && actor_limit > 0 && static_cast<int>(ap_map.size()) >= actor_limit)
				return monostate{};
			return nullopt;
		},
		scanner.get(SK::iface),
		"type mgt subtype beacon or type data",
		seconds(timeout_sec)
	);

	nlohmann::json aps = nlohmann::json::array();
	int total_stas = 0;
	for(const auto &[bssid, entry]: ap_map){
		auto ap_json = entry.cfg.to_json();
		nlohmann::json sta_list = nlohmann::json::array();
		for(const auto &mac: entry.stations) sta_list.push_back(mac);
		ap_json["sta_count"] = static_cast<int>(entry.stations.size());
		ap_json["stations"]  = sta_list;
		aps.push_back(ap_json);
		total_stas += static_cast<int>(entry.stations.size());
	}

	rs.save_result({
		{"ap_count",   static_cast<int>(ap_map.size())},
		{"sta_count",  total_stas},
		{"aps",        aps},
	});
}

}