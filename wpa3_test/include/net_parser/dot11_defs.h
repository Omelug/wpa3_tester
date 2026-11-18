#pragma once
#include <cstdint>
#include <map>
#include <string_view>

// IEEE Std 802.11-2020, Section 9.3.3.2, Table 9-1
// "Valid type and subtype combinations"

namespace wpa3_tester::dot11 {

// MAC frame header field offsets from the start of the 802.11 frame
// IEEE 802.11-2020, Section 9.3.3.2, Figure 9-1
constexpr size_t FC_OFFSET    = 0;  // Frame Control (2 bytes)
constexpr size_t DUR_OFFSET   = 2;  // Duration/ID (2 bytes)
constexpr size_t ADDR1_OFFSET = 4;  // Address 1 - receiver (6 bytes)
constexpr size_t ADDR2_OFFSET = 10; // Address 2 - transmitter (6 bytes)
constexpr size_t ADDR3_OFFSET = 16; // Address 3 - BSSID/SA/DA (6 bytes)
constexpr size_t SEQCTL_OFFSET = 22; // Sequence Control (2 bytes)

// minimum bytes needed to access each address field
constexpr size_t ADDR1_END = ADDR1_OFFSET + 6; // 10
constexpr size_t ADDR2_END = ADDR2_OFFSET + 6; // 16
constexpr size_t ADDR3_END = ADDR3_OFFSET + 6; // 22

// Frame Type field (FC bits 3-2) - IEEE 802.11-2020, Section 9.2.4.1.3
constexpr uint8_t TYPE_MGMT = 0;
constexpr uint8_t TYPE_CTRL = 1;
constexpr uint8_t TYPE_DATA = 2;
constexpr uint8_t TYPE_EXT  = 3;
constexpr uint8_t FC_TYPE_SHIFT    = 2;
constexpr uint8_t FC_TYPE_MASK     = 0x03;
constexpr uint8_t FC_SUBTYPE_SHIFT = 4;
constexpr uint8_t FC_SUBTYPE_MASK  = 0x0F;
// 802.11 management frame header: FC(2)+Dur(2)+Addr1(6)+Addr2(6)+Addr3(6)+SeqCtrl(2)
constexpr size_t  MGMT_HDR_SIZE    = 24;

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

// Information Element tag IDs — IEEE 802.11-2020, Section 9.4.2, Table 9-92
// NOTE: incomplete, only IEs referenced in this project
enum IE : uint8_t {
	IE_SSID                  = 0x00,
	IE_RATES                 = 0x01,
	IE_DS_PARAM_SET          = 0x03,
	IE_TIM                   = 0x05,
	IE_COUNTRY               = 0x07,
	IE_CSA                   = 0x25, // Channel Switch Announcement
	IE_ERP_INFO              = 0x2A,
	IE_HT_CAPS               = 0x2D,
	IE_RSN                   = 0x30,
	IE_EXT_RATES             = 0x32,
	IE_SUPPORTED_OP_CLASSES  = 0x3B,
	IE_ECSA                  = 0x3C, // Extended CSA
	IE_HT_OPERATION          = 0x3D,
	IE_EXTENDED_CAPS         = 0x7F,
	IE_VHT_CAPS              = 0xBF,
	IE_VHT_OPERATION         = 0xC0,
	IE_VENDOR_SPECIFIC       = 0xDD,
};

inline const std::map<IE, std::string_view> ie_names = {
	{IE_SSID,                 "SSID"},
	{IE_RATES,                "SupportedRates"},
	{IE_DS_PARAM_SET,         "DSParamSet"},
	{IE_TIM,                  "TIM"},
	{IE_COUNTRY,              "Country"},
	{IE_CSA,                  "CSA"},
	{IE_ERP_INFO,             "ERPInfo"},
	{IE_HT_CAPS,              "HT-Caps"},
	{IE_RSN,                  "RSN"},
	{IE_EXT_RATES,            "ExtRates"},
	{IE_SUPPORTED_OP_CLASSES, "SupportedOpClasses"},
	{IE_ECSA,                 "ECSA"},
	{IE_HT_OPERATION,         "HT-Operation"},
	{IE_EXTENDED_CAPS,        "ExtendedCaps"},
	{IE_VHT_CAPS,             "VHT-Caps"},
	{IE_VHT_OPERATION,        "VHT-Operation"},
	{IE_VENDOR_SPECIFIC,      "VendorSpecific"},
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

inline std::string_view ie_to_string(const IE tag) {
	const auto it = ie_names.find(tag);
	return it != ie_names.end() ? it->second : "<unknown IE>";
}
inline std::string_view ie_to_string(uint8_t tag) { return ie_to_string(static_cast<IE>(tag)); }

}
