#include <chrono>
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
namespace{
bool add_station(ScanAP &scan_ap, const HWAddress<6> &mac, const char *via){
	if(!scan_ap.stations.emplace(mac).second) return false;
	log(LogLevel::DEBUG, "Station found via {}: {}", via, mac);
	return true;
}
}

bool parse_control_frame(const Dot11Control *ctrl, ScanAP &scan_ap){
	// RTS addr1 and addr2
	if(ctrl->subtype() == 11){
		const auto *d11rts = dynamic_cast<const Dot11RTS *>(ctrl);
		if(d11rts && d11rts->addr1() == scan_ap.bssid) return add_station(scan_ap, d11rts->target_addr(), "RTS");
	}
	return false;
}

bool parse_data_frame(const Dot11Data *data, ScanAP &scan_ap){
	const HWAddress<6> src = data->addr2();
	const HWAddress<6> dst = data->addr1();

	if(src == scan_ap.bssid || dst == scan_ap.bssid){
		const HWAddress<6> potential_sta = (src == scan_ap.bssid) ? dst : src;
		if(potential_sta != "ff:ff:ff:ff:ff:ff" && potential_sta != scan_ap.bssid)
			return add_station(scan_ap, potential_sta, "data frame");
	}
	return false;
}

bool parse_mgmt_frame(const Dot11ManagementFrame *mgmt, ScanAP &scan_ap){
	// Subtype 4 = Probe Request; 0/11 = Assoc Req / Auth
	if(mgmt->subtype() == 4) return add_station(scan_ap, mgmt->addr2(), "Probe Request");
	if(mgmt->subtype() == 0 || mgmt->subtype() == 11) return add_station(scan_ap, mgmt->addr2(), "Assoc Req/Auth");
	return false;
}

bool station_frame_parse(PDU &pdu, ScanAP &scan_ap){
	if(!pdu.find_pdu<Dot11>()) return false;

	bool capture = false;
	if(const auto mgmt = pdu.find_pdu<Dot11ManagementFrame>()){
		// management frames (beacon excluded)
		capture |= parse_mgmt_frame(mgmt, scan_ap);
	} else if(const auto data = pdu.find_pdu<Dot11Data>()){
		// data frames (Null function frames included)
		capture |= parse_data_frame(data, scan_ap);
	} else if(const auto ctrl = pdu.find_pdu<Dot11Control>()){
		// control frames (ACK, RTS, CTS)
		capture |= parse_control_frame(ctrl, scan_ap);
	}
	return capture;
}

void station_scan(ScanAP &scan_ap, const string &interface, const int timeout_sec, const filesystem::path &stations_pcap
){
	SnifferConfiguration sniff_config;
	sniff_config.set_snap_len(2000);
	sniff_config.set_timeout(1000);
	sniff_config.set_rfmon(true);

	// addr1 = receiver, addr2 = transmitter, addr3 = bssid
	const string filter = "wlan addr1 " + scan_ap.bssid.to_string() + " or wlan addr2 " + scan_ap.bssid.to_string();
	sniff_config.set_filter(filter);

	PacketWriter writer(stations_pcap, DataLinkType<RadioTap>());
	Sniffer sniffer(interface, sniff_config);

	log(LogLevel::INFO, "Starting station scan for AP {} (timeout: {}s)", scan_ap.bssid, timeout_sec);

	components::poll_sniffer<monostate>(sniffer.get_pcap_handle(), seconds(timeout_sec),
		[&](const uint8_t *pkt, const uint32_t caplen) ->optional<monostate>{
			try{
				RadioTap pdu(pkt, caplen);
				station_frame_parse(pdu, scan_ap);
				writer.write(pdu);
			} catch(const exception &e){
				log(LogLevel::WARNING, "station_scan: failed to parse frame: {}", e.what());
			}
			return nullopt; // keep scanning until timeout/interrupt
		});

	log(LogLevel::INFO, "Station scan finished. Found {} stations.", scan_ap.stations.size());
}

void fill_actor_caps_from_assoc_req(PDU &pdu, Actor_Config_external &cfg){
	const auto *mgmt = pdu.find_pdu<Dot11ManagementFrame>();
	if(!mgmt || (mgmt->subtype() != 0 && mgmt->subtype() != 2)) return;

	cfg.set(SK::mac, mgmt->addr2());

	apply_radiotap(pdu, cfg);
	apply_ht_vht_he(*mgmt, cfg);
	apply_rsn(*mgmt, cfg);

	set_role_flags(cfg, false);
}

Actor_Config_external scan_sta_actor(const string &iface, const string &bssid, const int timeout_sec){
	Actor_Config_external cfg;

	const string filter = "type mgt subtype assoc-req and ether addr1 " + bssid;
	components::poll_sniffer_pdu<monostate>([&](PDU &pdu) ->optional<monostate>{
		fill_actor_caps_from_assoc_req(pdu, cfg);
		return monostate{};
	}, iface, filter, seconds(timeout_sec));

	log(LogLevel::INFO, "scan_sta_actor {}: {}", bssid, cfg.to_str());
	return cfg;
}
}
