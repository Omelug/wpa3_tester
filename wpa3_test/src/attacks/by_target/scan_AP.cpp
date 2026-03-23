#include "attacks/by_target/scan_AP.h"

#include <tins/sniffer.h>
#include "config/RunStatus.h"
#include "observer/observers.h"
#include "scan/scan_EAP.h"

using namespace std;
using namespace filesystem;
using namespace Tins;
using namespace chrono;

namespace wpa3_tester::attack_scan{

    string ScanAP::to_tshark_str(const path &beacon_path) {
        if (!exists(beacon_path)) return "Error: File not found";
        const string command = "tshark -r " + beacon_path.string() +
                              " -T fields "
                              "-e wlan.ssid "
                              "-e wlan_mgt.rsn.akms "
                              "-e wlan_mgt.rsn.capabilities.mfpc "
                              "-e wlan_mgt.rsn.capabilities.mfpr "
                              "-E header=y 2>/dev/null";

        stringstream ss;
        array<char, 256> buffer;
        unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);
        if (!pipe) return "Error: popen failed";

        while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
            ss << buffer.data();
        }

        return ss.str();
    }
    
    void print_AKM(stringstream &ss, const RSNInformation::AKMSuites akm) {
        static const map<RSNInformation::AKMSuites, string> akm_map = {
            {RSNInformation::EAP,                "EAP"},
            {RSNInformation::PSK,                "PSK"},
            {RSNInformation::EAP_FT,             "EAP-FT"},
            {RSNInformation::PSK_FT,             "PSK-FT"},
            {RSNInformation::EAP_SHA256,         "EAP-SHA256"},
            {RSNInformation::PSK_SHA256,         "PSK-SHA256"},
            {RSNInformation::TDLS,               "TDLS"},
            {RSNInformation::SAE_SHA256,         "SAE_SHA256"},
            {RSNInformation::SAE_FT,             "SAE-FT"},
            {RSNInformation::EAP_SHA256_FIPSB,   "EAP-FIPS-B-256"},
            {RSNInformation::EAP_SHA384_FIPSB,   "EAP-FIPS-B-384"},
            {RSNInformation::EAP_SHA384,         "EAP-SHA384"}
        };

        auto it = akm_map.find(akm);
        if (it != akm_map.end()) {
            ss << it->second;
        } else {
            char buf[20];
            sprintf(buf, "UNKNOWN(0x%08x)", static_cast<uint32_t>(akm));
            ss << buf;
        }
    }
    void ScanAP::print_AKMs(stringstream &ss, const RSNInformation::akm_type &akms){
        ss << "AKM Suites: ";
        for (auto &akm : akms) {
            print_AKM(ss, akm);
            ss << " ";
        }
    }
    void print_capabilities(stringstream &ss, uint16_t caps){
        const bool mfpc = (caps & (1 << 7));  // Management Frame Protection Capable
        const bool mfpr = (caps & (1 << 6));  // Management Frame Protection Required
        const bool ocv  = (caps & (1 << 10)); // Operating Channel Validation
        const bool bprot = (caps & (1 << 11)); // Beacon Protection

        ss << "--- RSN Capabilities ---\n";
        ss << "MFP: " << (mfpr ? "REQUIRED" : (mfpc ? "Capable" : "No")) << "\n";
        ss << "OCV: " << (ocv ? "Yes" : "No") << "\n";
        ss << "Beacon Protection: " << (bprot ? "Yes" : "No") << "\n";
    }

    string ScanAP::to_str() const {
        stringstream ss;
        ss << "SSID: " << ssid << "\n";

        if (rsn.has_value()) {
            print_capabilities(ss, rsn->capabilities());
            print_AKMs(ss, rsn->akm_cyphers());
            ss << "\n";
        }

        ss << "Stations: " << stations.size() << "\n";
        for(const auto &mac: stations | views::keys) {
            ss << "  [STATION] " << mac << "\n";
        }

        return ss.str();
    }

    void RSN_scan(const string &cfg_mac, const string& interface, const int timeout_sec, ScanAP &scan_ap, const path &beacon_pcap) {
        SnifferConfiguration sniff_config;
        sniff_config.set_snap_len(2000);
        sniff_config.set_timeout(1000); // ms
        sniff_config.set_rfmon(true);   // Monitor mode

        const string filter = "(type mgt subtype beacon or type mgt subtype probe-resp) and ether addr2 " + cfg_mac;
        sniff_config.set_filter(filter);

        PacketWriter writer(beacon_pcap, DataLinkType<RadioTap>());

        Sniffer sniffer(interface, sniff_config);
        const auto start_time = steady_clock::now();
        bool beacon_saved = false;
        while (true){
            auto now = steady_clock::now();
            if (duration_cast<seconds>(now - start_time).count() >= timeout_sec) { break; }
            const unique_ptr<PDU> pdu(sniffer.next_packet());
            if (!pdu) continue;

            // Beacon (SSID, AKM, PMF, Channel)
            if (const auto beacon = pdu->find_pdu<Dot11Beacon>()) {

                scan_ap.ssid = beacon->ssid();
                scan_ap.rsn = beacon->rsn_information();

                if (!beacon_saved) {
                    writer.write(*pdu);
                    beacon_saved = true;
                }
            }
        }
    }

    void run_attack(RunStatus& rs) {
        const auto& att_cfg = rs.config.at("attack_config");
        const auto target_ap = rs.get_actor("target");
        const auto scanner = rs.get_actor("scanner");

        log(LogLevel::DEBUG, "Scanning start");
        ScanAP scan_ap{};
        if (att_cfg.value("beacon_scan", false)) {
            const auto timeout = att_cfg.value("beacon_timeout_sec", 10);
            log(LogLevel::DEBUG, "Scanning beacon for "+to_string(timeout)+" seconds");
            auto beacon_pcap = path(rs.run_folder) / (target_ap["actor_name"]+".pcap");
            RSN_scan(target_ap["mac"], scanner["iface"], timeout, scan_ap, beacon_pcap);
            ofstream ofs(path(rs.run_folder) / "beacon_scan.txt");
            ofs << "Scan results for " << target_ap["mac"] << "\n";
            ofs << scan_ap.to_str() << endl;
            ofs.close();
        }

        if(att_cfg.value("EAP_scan", false)){
            const auto timeout = att_cfg.value("EAP_timeout_sec", 10);
            log(LogLevel::DEBUG, "Scanning EAP for "+to_string(timeout)+" seconds");
            scan::active_eap_identity_scan(scanner["iface"], target_ap["mac"], timeout);
        }

        /*if (att_cfg.value("ACM", false)) {
            if (target_ap->bool_conditions["WPA3-SAE"].has_value()) {
                // Logika pro WPA3...
            }
        }*/
    }
}
