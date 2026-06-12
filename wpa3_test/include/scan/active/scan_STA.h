#pragma once
#include <filesystem>
#include <tins/pdu.h>
#include "config/Actor_Config/Actor_Config_external.h"
#include "scan/active/scan_AP.h"

namespace wpa3_tester::scan{

void station_scan(ScanAP &scan_ap, const std::string &interface, int timeout_sec,
				const std::filesystem::path &stations_pcap
);

// get info from beacon/probe-response PDU
// mac, ssid, channel, signal, band (GHz2_4/5/6), MFP/OCV/beacon_prot (RSN caps),
// w80211n/ac/ax (HT/VHT/HE IEs), ht_mode (HT Operation IE), AP/STA/managed/monitor flags
void fill_actor_caps_from_beacon(Tins::PDU &pdu, Actor_Config_external &cfg);

// passive beacon/probe-response scan
Actor_Config_external scan_ap_actor(const std::string &iface, const std::string &bssid, int timeout_sec);

// fill Actor_Config_external from an Association Request PDU
//  mac, signal, band, MFP/OCV/beacon_prot (RSN caps), w80211n/ac/ax, ht_mode, STA flags
void fill_actor_caps_from_assoc_req(Tins::PDU &pdu, Actor_Config_external &cfg);

// passive scan - wait for the first STA to send an Association Request
// returns on first success or timeout
Actor_Config_external scan_sta_actor(const std::string &iface, const std::string &bssid, int timeout_sec);

}