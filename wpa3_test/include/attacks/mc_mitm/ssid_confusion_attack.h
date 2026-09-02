#pragma once
#include "config/RunStatus.h"

namespace wpa3_tester::ssid_confusion{
void setup_attack(RunStatus & rs);
void run_attack(RunStatus & rs);
void stats_attack(const RunStatus &rs);
}