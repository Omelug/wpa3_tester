#pragma once
#include "config/RunStatus.h"
#include "system/wifi_channel.h"

namespace wpa3_tester::CSA_attack{
Tins::RadioTap get_CSA_beacon(const Tins::HWAddress<6> &ap_mac, const std::string &ssid, const Channel &ap_channel,
							const Channel &new_channel, int
							switch_count = 3);

void check_vulnerable(const Tins::HWAddress<6> &ap_mac, const Tins::HWAddress<6> &sta_mac,
					const std::string &iface_name, const std::string &ssid, const Channel &ap_channel,
					const Channel &new_channel,   int ms_interval, int attack_time);
void setup_chs_attack(RunStatus &rs);

// registered functions in tester
void setup_chs_attack(RunStatus & rs);
void run_chs_attack(RunStatus & rs);
void stats_chs_attack(const RunStatus &rs);

//help observer functions
void speed_observation_start(RunStatus & rs);
}