#pragma once
#include "config/RunStatus.h"

namespace wpa3_tester::ghost_attack {
// Ghost Attack — Lounis & Zulkernine 2019 (Bad-Token paper, Section 5.2)
// Race-condition inject a fake AP AssocResp (STATUS_INVALID_AKMP) before the real AP responds → STA aborts.
void setup_attack(RunStatus &rs);
void run_attack(RunStatus &rs);
void stats_attack(const RunStatus &rs);
}
