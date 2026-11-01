#pragma once
#include <string>
#include <tins/tins.h>
#include <unordered_map>

#include "attacks/sae_helper.h"
#include "config/RunStatus.h"

namespace wpa3_tester::cookie_guzzler {
void run_attack(RunStatus &rs);
void stats_attack(const RunStatus &rs);
std::optional<sae_helper::SAEPair> get_commit_values(RunStatus &rs, const std::string &iface,
	const std::string &sniff_iface, const std::string &ssid, const Tins::HWAddress<6> &ap_mac, int timeout,
	uint16_t sae_group = 0);
std::unordered_map<uint16_t, sae_helper::SAEPair> get_commit_values_all_groups(RunStatus &rs,
	const std::string &sniff_iface, const Tins::HWAddress<6> &ap_mac);
sae_helper::SAEPair make_probe_pair(uint16_t gid);
}
