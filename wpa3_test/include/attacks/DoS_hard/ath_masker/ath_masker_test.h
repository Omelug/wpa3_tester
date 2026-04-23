#pragma once
#include "config/RunStatus.h"

namespace wpa3_tester::ath_masker_test{
void setup_attack(RunStatus & rs);
void run_attack(RunStatus & rs);
void stats(const RunStatus &rs);
}