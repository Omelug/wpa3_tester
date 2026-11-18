#pragma once
#include <cstdint>
#include <map>
#include <string_view>

// IEEE Std 802.11-2020, Section 9.3.3.2, Table 9-1
// "Valid type and subtype combinations"

namespace wpa3_tester::dot11 {

// Frame Type field (FC bits 3-2)
constexpr uint8_t TYPE_MGMT = 0;
constexpr uint8_t TYPE_CTRL = 1;
constexpr uint8_t TYPE_DATA = 2;
constexpr uint8_t TYPE_EXT  = 3;

// Management frame subtypes (FC bits 7-4, Type=0b00)
inline const std::map<uint8_t, std::string_view> mgmt_subtype_names = {
	{0,  "AssocReq"},
	{1,  "AssocResp"},
	{2,  "ReassocReq"},
	{3,  "ReassocResp"},
	{4,  "ProbeReq"},
	{5,  "ProbeResp"},
	{6,  "TimingAdv"},
	// 7 reserved
	{8,  "Beacon"},
	{9,  "ATIM"},
	{10, "Disassoc"},
	{11, "Auth"},
	{12, "Deauth"},
	{13, "Action"},
	{14, "ActionNoAck"},
	// 15 reserved
};

// Control frame subtypes (FC bits 7-4, Type=0b01)
inline const std::map<uint8_t, std::string_view> ctrl_subtype_names = {
	// 0-1 reserved
	{2,  "Trigger"},
	{3,  "TACK"},
	{4,  "BFReportPoll"},
	{5,  "NDPAnnounce"},
	{6,  "CtrlExt"},
	{7,  "CtrlWrapper"},
	{8,  "BAR"},
	{9,  "BA"},
	{10, "PS-Poll"},
	{11, "RTS"},
	{12, "CTS"},
	{13, "ACK"},
	{14, "CF-End"},
	{15, "CF-End+CF-Ack"},
};

// Data frame subtypes (FC bits 7-4, Type=0b10)
inline const std::map<uint8_t, std::string_view> data_subtype_names = {
	{0,  "Data"},
	{1,  "Data+CF-Ack"},
	{2,  "Data+CF-Poll"},
	{3,  "Data+CF-Ack+CF-Poll"},
	{4,  "Null"},
	{5,  "CF-Ack"},
	{6,  "CF-Poll"},
	{7,  "CF-Ack+CF-Poll"},
	{8,  "QoS-Data"},
	{9,  "QoS-Data+CF-Ack"},
	{10, "QoS-Data+CF-Poll"},
	{11, "QoS-Data+CF-Ack+CF-Poll"},
	{12, "QoS-Null"},
	// 13 reserved
	{14, "QoS-CF-Poll"},
	{15, "QoS-CF-Ack+CF-Poll"},
};

inline std::string_view to_string(uint8_t type, uint8_t subtype) {
	const std::map<uint8_t, std::string_view> *names =
		type == TYPE_MGMT ? &mgmt_subtype_names :
		type == TYPE_CTRL ? &ctrl_subtype_names :
		type == TYPE_DATA ? &data_subtype_names : nullptr;
	if(names) {
		const auto it = names->find(subtype);
		if(it != names->end()) return it->second;
	}
	return "<invalid Dot11 frame>";
}

}
