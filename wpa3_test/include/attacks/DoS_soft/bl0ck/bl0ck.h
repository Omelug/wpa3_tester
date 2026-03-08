#pragma once
#include <string>
#include <tins/tins.h>
#include "config/RunStatus.h"

namespace wpa3_tester::bl0ck_attack{
    // Send a burst of bl0ck frames (BAR or BA)
    Tins::RadioTap get_bl0ck_frame(
        const Tins::HWAddress<6> &ap_hw,
        const Tins::HWAddress<6> &sta_hw,
        int subtype);

    // Send BAR or BA frames for the specified duration
    void block(const std::string& STA_mac,
               const std::string& AP_mac,
               const std::string& iface,
               int frame_num,
               const std::string& attack_type,
               int duration_sec,
               bool is_random);

    void setup_attack(RunStatus& rs);
    void run_bl0ck_attack(RunStatus& rs);
    void stats_bl0ck_attack(const RunStatus& rs);
    void speed_observation_start(RunStatus& rs);

    Tins::RadioTap get_BAR_frame(const Tins::HWAddress<6> &ap_hw, const Tins::HWAddress<6> &sta_hw);

}
