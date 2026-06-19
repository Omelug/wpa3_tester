#pragma once
#include "config/RunStatus.h"

using namespace std;

namespace wpa3_tester::components{
void setup_AP(RunStatus &rs, const string &actor_name);
void setup_STA(RunStatus &rs, const string &actor_name);
void client_ap_setup(RunStatus & rs);
void setup_rogue_ap(RunStatus & rs);
void client_ap_attacker_setup_enterprise(RunStatus & rs);
}