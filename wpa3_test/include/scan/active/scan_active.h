#pragma once
#include <cstdint>
#include <tins/pdu.h>
#include "config/Actor_Config/Actor_Config_external.h"

namespace wpa3_tester::scan{
void apply_radiotap(Tins::PDU & pdu, Actor_Config_external & cfg);
void apply_ht_vht_he(const Tins::Dot11ManagementFrame &mgmt, Actor_Config_external &cfg);
// Sets MFP/OCV/beacon_prot and WPA2-PSK/WPA3-SAE from the RSN IE of any management frame (beacon, assoc-req, …)
void apply_rsn(const Tins::Dot11ManagementFrame &mgmt, Actor_Config_external &cfg);

// RSN capabilities field (802.11 §9.4.2.24.4), decoded once and shared by apply_rsn() and ScanAP::to_str()
struct RSNCapFlags{
	bool mfp_capable;
	bool mfp_required;
	bool ocv;
	bool beacon_prot;
};
RSNCapFlags parse_rsn_caps(uint16_t caps);

// AP/STA/managed/monitor are mutually exclusive role flags set the same way for every scanned actor
void set_role_flags(Actor_Config_external &cfg, bool is_ap);
}
