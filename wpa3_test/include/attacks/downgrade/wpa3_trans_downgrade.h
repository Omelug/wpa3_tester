#pragma once
#include <string>
#include "config/RunStatus.h"

namespace wpa3_tester::wpa3_trans_downgrade{
bool check_vulnerable(const std::string &monitor_iface, const std::string &ssid, int wait_sec);
void setup_attack(RunStatus & rs);
void run_attack(RunStatus & rs);
void stats_attack(const RunStatus &rs);
}