#include <iostream>
#include <string>

#include "attacks/DoS_soft/channel_switch/channel_switch.h"
#include "system/hw_capabilities.h"

using namespace std;
using namespace Tins;
using namespace chrono;
using namespace wpa3_tester;

int main(const int argc, char *argv[]){
    if(argc != 9){
        cout << "Usage: " << argv[0] <<
                " <ap_mac> <sta_mac> <iface_name> <ssid> <ap_channel> <new_channel> <ms_interval> <attack_time>" <<
                endl;
        cout << "Example: " << argv[0] << " 00:11:22:33:44:55 aa:bb:cc:dd:ee:ff wlan0 test ssid 6 11 100 10" << endl;
        return 1;
    }

    const HWAddress<6> ap_mac(argv[1]);
    const HWAddress<6> sta_mac(argv[2]);
    const string iface_name = argv[3];
    const string ssid = argv[4];
    const Channel ap_channel{stoi(argv[5]), WifiBand::BAND_2_4_or_5, nullopt};
    const Channel new_channel{stoi(argv[6]),WifiBand::BAND_2_4_or_5, nullopt};
    const int ms_interval = stoi(argv[7]);
    const int attack_time = stoi(argv[8]);

    CSA_attack::check_vulnerable(ap_mac, sta_mac, iface_name, ssid, ap_channel, new_channel, ms_interval, attack_time);

    return 0;
}
