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
void setup_attack(RunStatus &rs){
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

void start_strict_tsharks(RunStatus &rs){
    const auto ap_mac = rs.get_actor("rogue_client")["mac"];
    const auto client_mac = rs.get_actor("rogue_ap")["mac"];

    const string mac_filter =
            "(wlan host " + ap_mac + " or wlan host " + client_mac + ")";

    observer::tshark::start_tshark(rs, "rogue_ap", mac_filter);
    observer::tshark::start_tshark(rs, "rogue_client", mac_filter);
}

void run_attack(RunStatus &rs){
    const auto rogue_client = rs.get_actor("rogue_client");
    const auto rogue_ap = rs.get_actor("rogue_ap");
    //const auto ap = rs.get_actor("access_point");
    //const auto client = rs.get_actor("client");

    const auto ap_ssid = rs.config.at("attack_config").at("ssid").get<string>();

    auto get_mac = [&](const string& actor_key, const string& config_key) -> string {
        if(rs.config.at("actors").contains(actor_key))
            return rs.get_actor(actor_key)["mac"];
        return rs.config.at("attack_config").at(config_key).get<string>();
    };

    const auto ap_mac     = get_mac("access_point", "target_ap_mac");
    const auto client_mac = get_mac("client", "target_client_mac");

    rs.start_observers();

    McMitm attack(
        rogue_client, rogue_ap,
        ap_ssid,
        ap_mac, client_mac,
        rs.config.at("attack_config").at("only_to_mitm").get<bool>());

    rogue_client->set_iface_up();
    rogue_ap->set_iface_up();

    //FIXME
    //start_strict_tsharks(rs);
    //rs.start_observers();

    //log(LogLevel::INFO, "Giving rogue AP one second to initialize ...");
    //this_thread::sleep_for(seconds(1));

    //TODO move to constrcutor
    attack.netconfig.real_channel = stoi(rogue_client["channel"]);
    attack.netconfig.rogue_channel = stoi(rogue_ap["channel"]);
    attack.netconfig.ssid = ap_ssid;

    attack.run(rs, rs.config.at("attack_config").at("attack_time").get<int>());
}

void stats(const RunStatus &rs){
    //TODO

    vector<unique_ptr<GraphElements>> elements;
    rs.log_events(elements,{
        {"access_point", "did not acknowledge authentication response", "ACK fail", "red"},
        {"client", "CTRL-EVENT-STARTED-CHANNEL-SWITCH", "SWITCH", "cyan"},
        {"client", "CTRL-EVENT-DISCONNECTED", "DISCONN", "red"},
        {"client", "@START", "START", "black"},
        {"client", "@END", "END", "black"},
    });

    vector<unique_ptr<GraphElements>> elements_ap = clone_elements(elements);;
    observer::tshark::pcap_events(rs, elements_ap,{
        //{"rogue_ap", "wlan.fc.type_subtype == 0x0008", "BEACON", "blue"},
        {"rogue_ap", "wlan.tag.number == 37", "CSA", "black"},
        {"rogue_ap", "wlan.fc.type_subtype == 0x0004 || wlan.fc.type_subtype == 0x0005", "PROBE", "cyan"},
        {"rogue_ap", "wlan.fc.type_subtype == 0x000b", "AUTH", "orange"},
        {"rogue_ap", "wlan.fc.type_subtype == 0x0000 || wlan.fc.type_subtype == 0x0001", "ASSOC", "green"},
        {"rogue_ap", "eapol", "EAPOL", "dark-green"},
    });
    observer::tshark::tshark_graph(rs, "rogue_ap", elements_ap);

    vector<unique_ptr<GraphElements>> elements_client = clone_elements(elements);;
    observer::tshark::pcap_events(rs, elements_client,{
        //{"rogue_client", "wlan.fc.type_subtype == 0x0008", "BEACON", "blue"},
        {"rogue_client", "wlan.tag.number == 37", "CSA", "black"},
        {"rogue_client", "wlan.fc.type_subtype == 0x000c", "DISCONN_packet", "pink"},
        {"rogue_client", "wlan.fc.type_subtype == 0x0004 || wlan.fc.type_subtype == 0x0005", "PROBE", "cyan"},
        {"rogue_client", "wlan.fc.type_subtype == 0x000b", "AUTH", "orange"},
        {"rogue_client", "wlan.fc.type_subtype == 0x0000 || wlan.fc.type_subtype == 0x0001", "ASSOC", "green"},
        {"rogue_client", "eapol", "EAPOL", "dark-green"},
    });
    observer::tshark::tshark_graph(rs, "rogue_client", elements_client);
}

}
