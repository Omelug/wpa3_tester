#pragma once
#include <libtins-src/include/tins/dot11/sae_dot11_auth.h>
#include <tins/hw_address.h>
#include "attacks/DoS_hard/cookie_guzzler/cookie_guzzler.h"
#include "logger/log.h"

using namespace std;
using namespace Tins;
namespace wpa3_tester::cookie_guzzler{
    dos_helpers::SAEPair capture_sae_commit(RunStatus &rs, const std::string &iface,
        const HWAddress<6> &ap_mac, int timeout_sec);
    void start_wpa_supplicant(const string &iface, const string &conf_path, const string &pid_file);
    void stop_wpa_supplicant(const string &pid_file);
}
