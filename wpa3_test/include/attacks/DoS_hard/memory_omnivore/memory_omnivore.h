#pragma once
#include <vector>
#include <tins/hw_address.h>
#include "config/RunStatus.h"

namespace wpa3_tester::memory_omnivore{
std::vector<Tins::HWAddress<6>> get_connected_stas(RunStatus & rs);
void setup_attack(RunStatus & rs);

void run_attack(RunStatus & rs);
void stats_attack(const RunStatus &rs);
}