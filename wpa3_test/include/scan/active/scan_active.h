#pragma once
#include <tins/pdu.h>
#include "config/Actor_Config/Actor_Config_external.h"

namespace wpa3_tester::scan{
void apply_radiotap(Tins::PDU & pdu, Actor_Config_external & cfg);
void apply_ht_vht_he(const Tins::Dot11ManagementFrame &mgmt, Actor_Config_external &cfg);
// Sets MFP/OCV/beacon_prot and WPA2-PSK/WPA3-SAE from the RSN IE of any management frame (beacon, assoc-req, …)
void apply_rsn(const Tins::Dot11ManagementFrame &mgmt, Actor_Config_external &cfg);
}
