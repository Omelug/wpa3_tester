#pragma once
#include <tins/tins.h>
#include <string>
#include <random>
#include "config/RunStatus.h"

using namespace std;
using namespace Tins;
using namespace chrono;

namespace wpa3_tester::cookie_guzzler{
    struct SAEPair {
        uint16_t group_id;
        std::vector<uint8_t> scalar;
        std::vector<uint8_t> element;
        bool success = false;
    };

    RadioTap get_cookie_guzzler_frame(const HWAddress<6> &ap_mac, const HWAddress<6> &sta_mac, const SAEPair &sae_params);
    void run_attack(RunStatus &rs);
    SAEPair get_commit_values(const string &iface,const string &sniff_iface, const string &ssid, const HWAddress<6> &ap_mac, int timeout, pcap_t *handler = nullptr);
}
