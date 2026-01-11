#pragma once
#include <iostream>
#include <tins/tins.h>
#include "config/RunStatus.h"

namespace wpa3_tester{
    void send_CSA_beacon(const Tins::HWAddress<6> &ap_mac,
                         const Tins::NetworkInterface &iface,
                         const std::string &ssid,
                         int ap_channel);

    void check_vulnerable(const Tins::HWAddress<6>& ap_mac,
                          const Tins::HWAddress<6>& sta_mac,
                          const std::string &iface_name,
                          const std::string& ssid,
                          int ap_channel,
                          int new_channel,
                          int ms_interval,
                          int attack_time);

    // registered functions in tester
    void setup_chs_attack(RunStatus& rs);
    void run_chs_attack(RunStatus& rs);
    void stats_chs_attack(const RunStatus &rs);

    //help observer functions
    void speed_observation_start(RunStatus& rs);
    void speed_observation_stop(RunStatus& rs);
}