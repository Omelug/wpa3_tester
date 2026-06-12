#include <chrono>
#include <set>
#include <variant>
#include <sys/poll.h>
#include <tins/sniffer.h>
#include "attacks/components/sniffer_helper.h"
#include "config/Actor_Config/Actor_Config_external.h"
#include "logger/log.h"
#include "scan/active/scan_active.h"
#include "scan/active/scan_AP.h"
#include "system/hw_capabilities.h"

using namespace std;
using namespace chrono;
using namespace Tins;

namespace wpa3_tester::scan{

// --------SCAN stations for AP --------------
bool parse_control_frame(const Dot11Control *ctrl, ScanAP &scan_ap){
	// RTS addr1 and addr2
	if(ctrl->subtype() == 11){
		auto *d11rts = dynamic_cast<const Dot11RTS *>(ctrl);
		const HWAddress<6> src = d11rts->target_addr(); // Transmitter (Station)
		if(d11rts->addr1() == scan_ap.bssid){
			if(scan_ap.stations.emplace(src).second){
				log(LogLevel::DEBUG, "Station found via RTS: {}", scan_ap.bssid);
				return true;
			}
		}
	}
	return false;
}

bool parse_data_frame(const Dot11Data *data, ScanAP &scan_ap){
	const HWAddress<6> src = data->addr2();
	const HWAddress<6> dst = data->addr1();

	if(src == scan_ap.bssid || dst == scan_ap.bssid){
		const HWAddress<6> potential_sta = (src == scan_ap.bssid) ? dst : src;
		if(potential_sta != "ff:ff:ff:ff:ff:ff" && potential_sta != scan_ap.bssid){
			if(scan_ap.stations.emplace(potential_sta).second){
				log(LogLevel::DEBUG, "Station found : {}", potential_sta);
				return true;
			}
		}
	}
	return false;
}

bool parse_mgmt_frame(const Dot11ManagementFrame *mgmt, ScanAP &scan_ap){
	// Subtype 4 = Probe Request
	if(mgmt->subtype() == 4){
		const HWAddress<6> sta_mac = mgmt->addr2(); // Transmitter
		if(scan_ap.stations.insert(sta_mac).second){
			log(LogLevel::DEBUG, "Station found via Probe Request: {}", sta_mac);
			return true;
		}
	} else if(mgmt->subtype() == 0 || mgmt->subtype() == 11){
		// Assoc Req / Auth
		if(scan_ap.stations.emplace(mgmt->addr2()).second){
			log(LogLevel::DEBUG, "Station found : {}", mgmt->addr2());
			return true;
		}
	}
	return false;
}

bool station_frame_parse(const unique_ptr<PDU> &pdu, ScanAP &scan_ap){
	if(!pdu) return false;
	const auto dot11 = pdu->find_pdu<Dot11>();
	if(!dot11) return false;

	bool capture = false;
	if(const auto mgmt = pdu->find_pdu<Dot11ManagementFrame>()){
		// management frames (beacon excluded)
		capture |= parse_mgmt_frame(mgmt, scan_ap);
	} else if(const auto data = pdu->find_pdu<Dot11Data>()){
		// data frames (Null function frames included)
		capture |= parse_data_frame(data, scan_ap);
	} else if(const auto ctrl = pdu->find_pdu<Dot11Control>()){
		// control frames (ACK, RTS, CTS)
		capture |= parse_control_frame(ctrl, scan_ap);
	}
	return capture;
}

void station_scan(ScanAP &scan_ap, const string &interface, const int timeout_sec,
				const filesystem::path &stations_pcap
){
	SnifferConfiguration sniff_config;
	sniff_config.set_snap_len(2000);
	sniff_config.set_timeout(1000);
	sniff_config.set_rfmon(true);

	// addr1 = receiver, addr2 = transmitter, addr3 = bssid
	const string filter = "wlan addr1 " + scan_ap.bssid + " or wlan addr2 " + scan_ap.bssid;
	sniff_config.set_filter(filter);

	PacketWriter writer(stations_pcap, DataLinkType<RadioTap>());
	Sniffer sniffer(interface, sniff_config);

	set<string> found_stations;
	const auto start_time = steady_clock::now();

	log(LogLevel::INFO, "Starting station scan for AP {} (timeout: {}s)", scan_ap.bssid, timeout_sec);

	while(true){
		auto now = steady_clock::now();
		if(duration_cast<seconds>(now - start_time).count() >= timeout_sec) break;

		unique_ptr<PDU> pdu(sniffer.next_packet());
		if(!pdu) continue;
		station_frame_parse(pdu, scan_ap);
		writer.write(*pdu);
	}
	log(LogLevel::INFO, "Station scan finished. Found {} stations.", scan_ap.stations.size());
}

void fill_actor_caps_from_assoc_req(PDU &pdu, Actor_Config_external &cfg){
	const auto *mgmt = pdu.find_pdu<Dot11ManagementFrame>();
	if(!mgmt || (mgmt->subtype() != 0 && mgmt->subtype() != 2)) return;

	cfg.set(SK::mac, mgmt->addr2().to_string());

	apply_radiotap(pdu, cfg);
	apply_ht_vht_he(*mgmt, cfg);
	apply_rsn(*mgmt, cfg);

	cfg.set(BK::AP,      false);
	cfg.set(BK::STA,     true);
	cfg.set(BK::managed, false);
	cfg.set(BK::monitor, false);
}

Actor_Config_external scan_sta_actor(const string &iface, const string &bssid, const int timeout_sec){
	Actor_Config_external cfg;

	const string filter = "type mgt subtype assoc-req and ether addr1 " + bssid;
	components::poll_sniffer_pdu<monostate>(
		[&](PDU &pdu) -> optional<monostate>{
			fill_actor_caps_from_assoc_req(pdu, cfg);
			return monostate{};
		},
		iface, filter, seconds(timeout_sec)
	);

	log(LogLevel::INFO, "scan_sta_actor {}: {}", bssid, cfg.to_str());
	return cfg;
}
}
