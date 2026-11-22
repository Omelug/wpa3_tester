#pragma once
#include "config/RunStatus.h"
namespace wpa3_tester::peer_deceiver {
// WPA3 connection deprivation - Lounis & Zulkernine [19] (cited in Chatzoglou 2022, Section 7)
// Inject spoofed SAE rejection (STATUS_UNSUPPORTED_GROUP) faster than the AP, preventing STA auth.
void setup_attack(RunStatus &rs);
void run_attack(RunStatus &rs);
void stats_attack(const RunStatus &rs);
}
