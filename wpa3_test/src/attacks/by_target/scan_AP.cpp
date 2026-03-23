#include "attacks/by_target/scan_AP.h"

#include <libtins-src/include/tins/rsn_information.h>
#include <tins/sniffer.h>

#include "config/RunStatus.h"
#include "observer/observers.h"
#include <tins/dot11/dot11_beacon.h>

using namespace std;
using namespace filesystem;
using namespace Tins;
using namespace chrono;

namespace wpa3_tester::attack_scan{

    void RSN_scan(const string &cfg_mac, const std::string& interface, const int timeout_sec, Scan_AP &scan_ap) {
        SnifferConfiguration sniff_config;
        sniff_config.set_snap_len(2000);
        sniff_config.set_timeout(1000); // ms
        sniff_config.set_rfmon(true);   // Monitor mode

        const string filter = "type mgt subtype beacon or probe-resp and ether addr2 " + cfg_mac;
        sniff_config.set_filter(filter);

        Sniffer sniffer(interface, sniff_config);
        const auto start_time = steady_clock::now();
        while (true){
            auto now = steady_clock::now();
            if (duration_cast<seconds>(now - start_time).count() >= timeout_sec) { break; }
            const unique_ptr<PDU> pdu(sniffer.next_packet());
            if (!pdu) continue;

            // 1. Získání informací z Beaconu (SSID, AKM, PMF, Channel)
            if (const auto beacon = pdu->find_pdu<Dot11Beacon>()) {
                scan_ap.ssid = beacon->ssid();
                scan_ap.rsn = beacon->rsn_information();
            }
        }
    }

    void run_attack(RunStatus& rs) {
        const auto& att_cfg = rs.config.at("attack_config");
        const auto target_ap = rs.get_actor("target");
        const auto scanner = rs.get_actor("scanner");

        Scan_AP scan_ap{};
        if (att_cfg.value("beacon_scan", false)) {
            const auto timeout = att_cfg.value("beacon_timeout_sec", 10);
            RSN_scan(target_ap["mac"], scanner["iface"], timeout, scan_ap);
            ofstream ofs(path(rs.run_folder) / "beacon_scan.txt");
            ofs << "Scan results for " << target_ap["mac"] << ":\n";
            ofs << scan_ap.to_str() << endl;
        }

        /*if (att_cfg.value("ACM", false)) {
            if (target_ap->bool_conditions["WPA3-SAE"].has_value()) {
                // Logika pro WPA3...
            }
        }*/
    }
}
