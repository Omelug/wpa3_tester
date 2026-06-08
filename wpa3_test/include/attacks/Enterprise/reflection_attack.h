#pragma once
#include "eap_helper.h"

namespace wpa3_tester::reflection{

bool run_reflection_exchange(EAP_Att &eap_att);

void setup_attack(RunStatus & rs);
void run_attack(RunStatus & rs);
}
