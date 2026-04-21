#include "attacks/by_target/scan_AP.h"
#include "attacks/components/setup_connections.h"
#include "attacks/DoS_soft/channel_switch/channel_switch.h"
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
        //components::client_ap_attacker_setup(rs);

        //TODO components::setup_STA(rs, "client");
        //rs.process_manager.wait_for("client", "EVENT-CONNECTED", seconds(40));


        //const auto ap        = rs.get_actor("access_point");
        //const auto rogue_client = rs.get_actor("rogue_client");
        //const auto rogue_ap = rs.get_actor("rogue_ap");

        /*
        //TODO only for  2.4 GHz
        rogue_client->str_con["channel"] = ap["channel"];
        // rogue channel that doesn't overlap the real one - 1-11 are global valid channels //TODO check
        rogue_ap->str_con["channel"] = to_string((stoi(ap["channel"]) >= 6) ? 1 : 11);
        */
    }

    void start_strict_tsharks(RunStatus& rs){
        const auto ap_mac = rs.get_actor("rogue_client")["mac"];
        const auto client_mac = rs.get_actor("rogue_ap")["mac"];

        const string mac_filter =
        "(wlan host "+ ap_mac +" or wlan host "+client_mac+")";

        observer::tshark::start_tshark(rs, "rogue_ap", mac_filter);
        observer::tshark::start_tshark(rs, "rogue_client", mac_filter);
    }


    void run_attack(RunStatus& rs){
        const auto rogue_client = rs.get_actor("rogue_client");
        const auto rogue_ap = rs.get_actor("rogue_ap");
        //const auto ap = rs.get_actor("access_point");
        //const auto client = rs.get_actor("client");

        const auto ap_ssid = rs.config.at("attack_config").at("ssid").get<string>();
        const auto ap_mac = rs.config.at("attack_config").at("target_ap_mac").get<string>();
        const auto client_mac = rs.config.at("attack_config").at("target_client_mac").get<string>();

        const HWAddress<6> ap_csa_mac(rs.get_actor("access_point")["mac"]);
        const HWAddress<6> sta_mac(rs.get_actor("client")["mac"]);

        rs.start_observers();

        McMitm attack(
            rogue_client["iface"], rogue_ap["iface"],
            ap_ssid,
            ap_mac, client_mac);


        rogue_client->up_iface();
        rogue_ap->up_iface();

        //FIXME
        //start_strict_tsharks(rs);
        //rs.start_observers();

        //log(LogLevel::INFO, "Giving rogue AP one second to initialize ...");
        //this_thread::sleep_for(seconds(1));

        //TODO move to constrcutor
        attack.netconfig.real_channel = stoi(rogue_client["channel"]);
        attack.netconfig.rogue_channel = stoi(rogue_ap["channel"]);
        attack.netconfig.ssid = ap_ssid;

        /*CSA_attack::check_vulnerable(
            ap_mac, client_mac,
             rogue_client["iface"], ap_ssid,
            attack.netconfig.real_channel,  attack.netconfig.rogue_channel, 100, 7);
        */
        attack.run(rs, rs.config.at("attack_config").at("attack_time").get<int>());
    }

    void stats(const RunStatus& rs){
        //TODO
        /*vector<GraphElement> events;
        events.push_back({get_time_logs(rs, "client", "CTRL-EVENT-STARTED-CHANNEL-SWITCH"),"SWITCH","blue"});
        events.push_back({get_time_logs(rs, "client", "CTRL-EVENT-DISCONNECTED"),"DISCONN","red"});
        events.push_back({get_time_logs(rs, "client", "@START"),"START","black"});
        events.push_back({get_time_logs(rs, "client", "@END"),"END","black"});

        //observer::tshark_graph(rs, "client", events);
        observer::tshark_graph(rs, "rogue_ap", events);*/
    }
}
