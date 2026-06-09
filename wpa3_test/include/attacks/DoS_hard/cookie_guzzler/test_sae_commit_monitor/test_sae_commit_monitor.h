#pragma once
#include "config/RunStatus.h"

namespace wpa3_tester::test_sae_commit_monitor{
void speed_observation_start(RunStatus & rs);
void run_attack(RunStatus & rs);
void stats_attack(const RunStatus &rs);
}