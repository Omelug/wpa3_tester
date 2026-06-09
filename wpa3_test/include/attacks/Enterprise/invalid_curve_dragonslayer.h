#pragma once
#include "config/RunStatus.h"

namespace wpa3_tester::invalid_curve_dragonslayer{
	void setup_attack(RunStatus & rs);
	void run_attack(RunStatus & rs);
}