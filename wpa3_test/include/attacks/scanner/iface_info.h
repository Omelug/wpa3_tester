#pragma once
#include "config/RunStatus.h"

namespace wpa3_tester::iface_info{
void run_attack(RunStatus &rs);
void generate_report(const RunStatus &rs);
void stats_attack(const RunStatus &rs);
}
