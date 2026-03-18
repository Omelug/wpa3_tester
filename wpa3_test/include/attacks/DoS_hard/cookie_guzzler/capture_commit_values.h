#pragma once
#include <tins/hw_address.h>
#include "attacks/DoS_hard/cookie_guzzler/cookie_guzzler.h"

namespace Tins{
    class RawPDU;
    class Dot11Authentication;
}

using namespace std;
using namespace Tins;
namespace wpa3_tester::cookie_guzzler{

    SAEPair capture_sae_commit(const std::string &iface, const HWAddress<6> &ap_mac, int timeout_sec);
    void start_wpa_supplicant(const string &iface, const string &conf_path, const string &pid_file);
    void stop_wpa_supplicant(const string &pid_file);
}
