#pragma once
#include "config/RunStatus.h"

using namespace std;

namespace wpa3_tester::components{
void setup_AP(RunStatus &rs, const string &actor_name);
void stop_AP(RunStatus &rs, const string &actor_name);
void setup_STA(RunStatus &rs, const string &actor_name);
void client_ap_setup(RunStatus & rs, bool check_way_eapol);
inline void client_ap_setup_t(RunStatus & rs){ client_ap_setup(rs, true); }
void setup_rogue_ap(RunStatus & rs);
void client_ap_attacker_setup_enterprise(RunStatus & rs);
}
