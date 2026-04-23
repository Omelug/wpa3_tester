#pragma once
#include <tins/tins.h>
#include <string>
#include <random>

#include "attacks/DoS_hard/dos_helpers.h"
#include "config/RunStatus.h"

namespace wpa3_tester::cookie_guzzler{
Tins::RadioTap get_cookie_guzzler_frame(const Tins::HWAddress<6> &ap_mac,
                                        const Tins::HWAddress<6> &sta_mac, const dos_helpers::SAEPair &sae_params
);
void run_attack(RunStatus & rs);
void stats_attack(const RunStatus &rs);
std::optional<dos_helpers::SAEPair> get_commit_values(RunStatus &rs,
                                                      const std::string &iface, const std::string &sniff_iface,
                                                      const std::string &ssid,
                                                      const Tins::HWAddress<6> &ap_mac, int timeout,
                                                      pcap_t *handler = nullptr
);
}