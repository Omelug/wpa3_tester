#pragma once
#include "config/RunStatus.h"

namespace wpa3_tester::deauth_attack {

Tins::RadioTap make_deauth(const Tins::HWAddress<6> &ap_mac, const Tins::HWAddress<6> &sta_mac);
void setup_attack(RunStatus &rs);
void run_attack(RunStatus &rs);
void stats_attack(const RunStatus &rs);

}
