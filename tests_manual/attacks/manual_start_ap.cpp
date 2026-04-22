#include <iostream>
#include <string>
#include <tins/tins.h>

#include "pcap_helper.h"
#include "attacks/mc_mitm/wifi_util.h"
#include "config/RunStatus.h"
#include "logger/log.h"

using namespace std;
using namespace Tins;
using namespace wpa3_tester;

int main(const int argc, char* argv[]) {
    if (argc < 2) {
        cout << "Usage: " << argv[0] << " <base_iface>" << endl;
        cout << "Example: " << argv[0] << " wlan0" << endl;
        return 1;
    }

    const string base_iface = argv[1];
    const string ap_iface   = "ap_" + base_iface;
    constexpr int    channel    = 1;
    const string pcap_path  = string(PROJECT_ROOT_DIR) + "/../tests/attacks/mc_mitm/beacon_test.pcapng";

    log(LogLevel::INFO, "base_iface: " + base_iface);
    log(LogLevel::INFO, "ap_iface:   " + ap_iface);
    log(LogLevel::INFO, "channel:    " + to_string(channel));
    log(LogLevel::INFO, "pcap:       " + pcap_path);

    const auto raw = test_helpers::read_pcap_file(pcap_path);
    RadioTap rt(raw.data(), raw.size());
    const Dot11Beacon beacon = rt.rfind_pdu<Dot11Beacon>();
    log(LogLevel::INFO, "Beacon loaded, SSID: " + get_ssid(beacon));

    RunStatus rs;
    start_ap(rs, ap_iface, base_iface, channel, beacon);

    log(LogLevel::INFO, "start_ap returned — AP should be up on " + ap_iface);
    cout << "Press Enter to stop AP..." << endl;
    cin.get();

    stop_ap(ap_iface);
    log(LogLevel::INFO, "AP stopped");

    return 0;
}
