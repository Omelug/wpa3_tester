#pragma once
#include "config/RunStatus.h"

namespace wpa3_tester::wpa3_trans_downgrade {
	void setup_attack(RunStatus &rs);
	void run_attack(RunStatus &rs);
	void stats_attack(const RunStatus &rs);
}