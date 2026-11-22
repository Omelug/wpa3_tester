#pragma once
#include "config/RunStatus.h"

namespace wpa3_tester::bad_token {
// Bad-Token attack — Lounis & Zulkernine 2019 (Bad-Token: Denial of Service Attacks on WPA3)
// Sniff AP SAE Commit replies; inject fake STA Confirm with wrong token → AP rejects the legitimate STA.
void setup_attack(RunStatus &rs);
void run_attack(RunStatus &rs);
void stats_attack(const RunStatus &rs);
}
