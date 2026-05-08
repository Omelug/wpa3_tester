#pragma once
#include "config/RunStatus.h"

namespace wpa3_tester::sae_dos_wrapper{
void setup_attack(RunStatus &rs);
void run_attack(RunStatus &rs);
void stats_attack(const RunStatus &rs);
}
