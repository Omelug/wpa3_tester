#include <chrono>
#include <set>
#include <tins/rawpdu.h>
#include <tins/sniffer.h>
#include <sys/poll.h>

#include "attacks/by_target/scan_AP.h"
#include "logger/log.h"

using namespace std;
using namespace chrono;
using namespace Tins;

namespace wpa3_tester::scan{
bool parse_control_frame(const Dot11Control *ctrl, attack_scan::ScanAP &scan_ap){
    string addr1 = ctrl->addr1().to_string();

    // RTS addr1 and addr2
    if(ctrl->subtype() == 11){
        auto *d11rts = static_cast<const Dot11RTS *>(ctrl);
        const string src = d11rts->target_addr().to_string(); // Transmitter (Station)
        if(d11rts->addr1().to_string() == scan_ap.bssid){
            if(scan_ap.stations.emplace(attack_scan::Scan_STA(src)).second){
                log(LogLevel::DEBUG, "Station found via RTS: " + scan_ap.bssid);
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
            if(scan_ap.stations.emplace(attack_scan::Scan_STA(potential_sta)).second){
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
    //const string& ap_mac, set<string>& found_stations) {
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
}