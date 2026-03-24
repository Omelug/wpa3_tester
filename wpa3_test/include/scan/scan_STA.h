#pragma once
#include <filesystem>
#include <set>
#include <libtins-src/include/tins/pdu.h>
#include "attacks/by_target/scan_AP.h"

namespace wpa3_tester::scan{
    void station_scan(attack_scan::ScanAP &scan_ap, const std::string& interface, const int timeout_sec, const std::filesystem::path &stations_pcap);
    void station_frame_parse(const Tins::PDU* pdu, const std::string& ap_mac, std::set<std::string>& found_stations);
}