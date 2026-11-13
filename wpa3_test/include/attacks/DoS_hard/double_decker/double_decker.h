#pragma once
#include "config/RunStatus.h"

namespace wpa3_tester::double_decker {
void run_attack(RunStatus &rs);
void stats_attack(const RunStatus &rs);
}
