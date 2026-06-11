#pragma once
#include "config/RunStatus.h"

namespace wpa3_tester::sta_info{

void setup_attack(RunStatus &rs);
void run_attack(RunStatus &rs);

}