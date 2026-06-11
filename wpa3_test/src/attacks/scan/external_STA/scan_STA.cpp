#include <chrono>
#include <set>
#include <variant>
#include <sys/poll.h>
#include <tins/sniffer.h>

#include "attacks/scan/scan_AP.h"
#include "attacks/scan/scan_STA.h"
#include "attacks/components/sniffer_helper.h"
#include "config/Actor_Config/Actor_Config_external.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"

using namespace std;
using namespace chrono;
using namespace Tins;

namespace wpa3_tester::scan{
bool parse_control_frame(const Dot11Control *ctrl, attack_scan::ScanAP &scan_ap){
	string addr1 = ctrl->addr1().to_string();

	// RTS addr1 and addr2
	if(ctrl->subtype() == 11){
		auto *d11rts = dynamic_cast<const Dot11RTS *>(ctrl);
		const string src = d11rts->target_addr().to_string(); // Transmitter (Station)
		if(d11rts->addr1().to_string() == scan_ap.bssid){
			if(scan_ap.stations.emplace(src).second){
				log(LogLevel::DEBUG, "Station found via RTS: {}", scan_ap.bssid);
				return true;
			}
		}
	}
	return false;
}

bool parse_data_frame(const Dot11Data *data, attack_scan::ScanAP &scan_ap){
	const string src = data->addr2().to_string();
	const string dst = data->addr1().to_string();

	if(src == scan_ap.bssid || dst == scan_ap.bssid){
		const string potential_sta = (src == scan_ap.bssid) ? dst : src;
		if(potential_sta != "ff:ff:ff:ff:ff:ff" && potential_sta != scan_ap.bssid){
			if(scan_ap.stations.emplace(potential_sta).second){
				log(LogLevel::DEBUG, "Station found : {}", potential_sta);
				return true;
			}
		}
	}
	return false;
}

bool parse_mgmt_frame(const Dot11ManagementFrame *mgmt, attack_scan::ScanAP &scan_ap){
	// Subtype 4 = Probe Request
	if(mgmt->subtype() == 4){
		const string sta_mac = mgmt->addr2().to_string(); // Transmitter
		if(scan_ap.stations.insert(attack_scan::Scan_STA(sta_mac)).second){
			log(LogLevel::DEBUG, "Station found via Probe Request: {}", sta_mac);
			return true;
		}
	} else if(mgmt->subtype() == 0 || mgmt->subtype() == 11){
		// Assoc Req / Auth
		if(scan_ap.stations.emplace(mgmt->addr2().to_string()).second){
			log(LogLevel::DEBUG, "Station found : {}", mgmt->addr2().to_string());
			return true;
		}
	}
	return false;
}

bool station_frame_parse(const unique_ptr<PDU> &pdu, attack_scan::ScanAP &scan_ap){
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

void station_scan(attack_scan::ScanAP &scan_ap, const string &interface, const int timeout_sec,
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

// ---- scan_ap_actor helpers ----

static void apply_radiotap(PDU &pdu, Actor_Config_external &cfg){
	const auto *rt = pdu.find_pdu<RadioTap>();
	if(!rt) return;
	try{ cfg.set(SK::signal, to_string(rt->dbm_signal())); } catch(...){}
	try{
		const int freq = rt->channel_freq();
		if(freq > 0){
			cfg.set(SK::channel, to_string(hw_capabilities::freq_to_channel(freq)));
			if     (freq >= 2412 && freq <= 2484){ cfg.set(BK::GHz2_4, true); cfg.set(BK::GHz5, false); cfg.set(BK::GHz6, false); }
			else if(freq >= 5170 && freq <= 5885){ cfg.set(BK::GHz2_4, false); cfg.set(BK::GHz5, true);  cfg.set(BK::GHz6, false); }
			else if(freq >= 5945 && freq <= 7125){ cfg.set(BK::GHz2_4, false); cfg.set(BK::GHz5, false); cfg.set(BK::GHz6, true);  }
		}
	} catch(...){}
}

static void apply_rsn_caps(const Dot11Beacon &beacon, Actor_Config_external &cfg){
	try{
		const auto rsn = beacon.rsn_information();
		const uint16_t caps = rsn.capabilities();
		cfg.set(BK::MFP,         static_cast<bool>(caps & (1u << 7)));   // mfpc
		cfg.set(BK::OCV,         static_cast<bool>(caps & (1u << 10)));
		cfg.set(BK::beacon_prot, static_cast<bool>(caps & (1u << 11)));
	} catch(...){}
}

static void apply_ht_vht_he(const Dot11ManagementFrame &mgmt, Actor_Config_external &cfg){
	using OT = Dot11ManagementFrame::OptionTypes;

	// HT Capabilities (IE 45) → 802.11n
	const bool has_ht = mgmt.search_option(OT::HT_CAPABILITY) != nullptr;
	cfg.set(BK::w80211n, has_ht);

	if(has_ht){
		// HT Operation (IE 61): byte 1 bits 0-1 = secondary channel offset
		// 0=none(HT20), 1=above(HT40+), 3=below(HT40-)
		const auto *ht_op = mgmt.search_option(OT::HT_OPERATION);
		if(ht_op && ht_op->data_size() >= 2){
			switch(ht_op->data_ptr()[1] & 0x03){
				case 1:  cfg.set(SK::ht_mode, "HT40+"); break;
				case 3:  cfg.set(SK::ht_mode, "HT40-"); break;
				default: cfg.set(SK::ht_mode, "HT20");  break;
			}
		} else{
			cfg.set(SK::ht_mode, "HT20");
		}
	}

	// VHT Capabilities (IE 191) → 802.11ac
	cfg.set(BK::w80211ac, mgmt.search_option(OT::VHT_CAP) != nullptr);

	// HE Capabilities: extension element (IE 255, ext ID 35) → 802.11ax
	// Iterate all options to find the multi-occurrence extension element.
	bool has_he = false;
	for(const auto &opt: mgmt.options()){
		if(opt.option() == static_cast<OT>(255) && opt.data_size() > 0 && opt.data_ptr()[0] == 35){
			has_he = true;
			break;
		}
	}
	cfg.set(BK::w80211ax, has_he);
}

void fill_actor_caps_from_beacon(PDU &pdu, Actor_Config_external &cfg){
	const auto *beacon = pdu.find_pdu<Dot11Beacon>();
	if(!beacon) return;

	cfg.set(SK::mac, beacon->addr2().to_string());
	try{ cfg.set(SK::ssid, beacon->ssid()); } catch(...){}

	apply_radiotap(pdu, cfg);

	// Channel fallback from DS Parameter Set if RadioTap had no frequency
	if(!cfg[SK::channel].has_value()){
		try{ cfg.set(SK::channel, to_string(beacon->ds_parameter_set())); } catch(...){}
	}

	apply_rsn_caps(*beacon, cfg);
	apply_ht_vht_he(*beacon, cfg);

	cfg.set(BK::AP,      true);
	cfg.set(BK::STA,     false);
	cfg.set(BK::managed, false);
	cfg.set(BK::monitor, false);
}

Actor_Config_external scan_ap_actor(const string &iface, const string &bssid, const int timeout_sec){
	Actor_Config_external cfg;
	cfg.set(SK::mac, bssid);

	const string filter = "(type mgt subtype beacon or type mgt subtype probe-resp) and ether addr2 " + bssid;
	components::poll_sniffer_pdu<monostate>(
		[&](PDU &pdu) -> optional<monostate>{
			fill_actor_caps_from_beacon(pdu, cfg);
			return monostate{};
		},
		iface, filter, seconds(timeout_sec)
	);

	log(LogLevel::INFO, "scan_ap_actor {}: {}", bssid, cfg.to_str());
	return cfg;
}

// TODO: scan_sta_actor_assoc(iface, sta_mac, ssid, password, timeout_sec)
// Create a fake AP (hostapd) matching the target SSID/credentials,
// wait for sta_mac to associate, parse Association Request IEs to fill
// w80211n/ac/ax, ht_mode, and SK::ip_addr (from DHCP exchange).
}
