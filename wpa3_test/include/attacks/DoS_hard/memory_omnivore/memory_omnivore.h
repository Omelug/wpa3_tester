#pragma once
#include "config/RunStatus.h"

namespace wpa3_tester::memory_omnivore{
void setup_attack(RunStatus & rs);

void run_attack(RunStatus & rs);
void stats_attack(const RunStatus &rs);
}