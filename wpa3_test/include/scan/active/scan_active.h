#pragma once
#include <tins/pdu.h>
#include <tins/dot11.h>
#include "config/Actor_Config/Actor_Config_external.h"

namespace wpa3_tester::scan{

void apply_radiotap(Tins::PDU &pdu, Actor_Config_external &cfg);
void apply_ht_vht_he(const Tins::Dot11ManagementFrame &mgmt, Actor_Config_external &cfg);

}
