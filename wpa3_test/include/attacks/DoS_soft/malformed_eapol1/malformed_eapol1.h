#pragma once
#include <tins/hw_address.h>

namespace wpa3_tester::eapol_logoff{
Tins::RadioTap get_malformed_eapol(const Tins::HWAddress<6> &ap_mac, const Tins::HWAddress<6> &sta_mac, int ap_channel);
void speed_observation_start(RunStatus & rs);
void setup_attack(RunStatus & rs);
void run_attack(RunStatus & rs);
void stats(const RunStatus &rs);
}