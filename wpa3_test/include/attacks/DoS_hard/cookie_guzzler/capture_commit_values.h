#pragma once
#include <tins/hw_address.h>
#include "attacks/DoS_hard/cookie_guzzler/cookie_guzzler.h"
#include "logger/log.h"

namespace wpa3_tester::cookie_guzzler{
    std::optional<dos_helpers::SAEPair> capture_sae_commit(RunStatus &rs, const std::string &iface,
        const Tins::HWAddress<6> &ap_mac, int timeout_sec);
    void start_wpa_supplicant(const std::string &iface, const std::string &conf_path, const std::string &pid_file);
    void stop_wpa_supplicant(const std::string &pid_file);
}
