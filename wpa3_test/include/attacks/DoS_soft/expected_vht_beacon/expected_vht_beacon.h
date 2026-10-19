#pragma once
#include "config/RunStatus.h"

namespace wpa3_tester::expected_vht_beacon_attack {

Tins::Dot11Beacon build_legacy_beacon(const Tins::Dot11Beacon &src);
void setup_attack(RunStatus &rs);
void run_attack(RunStatus &rs);
void stats_attack(const RunStatus &rs);

}
