#pragma once
#include <optional>
#include <string>
#include "config/RunStatus.h"
#include "system/wifi_channel.h"

namespace wpa3_tester::CSA_attack {

constexpr int CHANNEL_SWITCH_MAX = 3;
Tins::RadioTap get_CSA_beacon(const Tins::HWAddress<6> &ap_mac, const Channel &ap_channel,
		const Channel &new_channel, int switch_count = 3, const Tins::Dot11Beacon *src_beacon = nullptr);

void check_vulnerable(const Tins::HWAddress<6> &ap_mac, const Tins::HWAddress<6> &sta_mac,
		const std::string &iface_name, const std::string &ssid, const Channel &ap_channel, const Channel &new_channel,
		int ms_interval, int attack_time, const std::optional<std::string> &netns = std::nullopt);
void setup_chs_attack(RunStatus &rs);

// registered functions in tester
void run_attack(RunStatus &rs);
void stats_attack(const RunStatus &rs);

//help observer functions
void speed_observation_start(RunStatus &rs);
}