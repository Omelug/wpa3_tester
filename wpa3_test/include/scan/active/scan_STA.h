#pragma once
#include <filesystem>
#include <tins/pdu.h>
#include "config/Actor_Config/Actor_Config_external.h"

namespace wpa3_tester::scan{
void station_scan(ScanAP &scan_ap, const std::string &interface, int timeout_sec,
				const std::filesystem::path &stations_pcap
);

// Fill Actor_Config_external with all AP capabilities extractable from a beacon/probe-response PDU.
// Covers: mac, ssid, channel, signal, band (GHz2_4/5/6), MFP/OCV/beacon_prot (RSN caps),
// w80211n/ac/ax (HT/VHT/HE IEs), ht_mode (HT Operation IE), AP/STA/managed/monitor flags.
void fill_actor_caps_from_beacon(Tins::PDU &pdu, Actor_Config_external &cfg);

// Passive beacon scan: capture one beacon/probe-response from bssid on iface,
// return Actor_Config_external with all extractable fields.
Actor_Config_external scan_ap_actor(const std::string &iface, const std::string &bssid, int timeout_sec);
}