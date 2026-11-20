#pragma once
#include <array>
#include <cstdint>
#include <map>
#include <string_view>

// IEEE Std 802.11-2020, Section 9.3.3.2, Table 9-1
// "Valid type and subtype combinations"

namespace wpa3_tester::dot11 {

// MAC frame header field offsets from the start of the 802.11 frame
// IEEE 802.11-2020, Section 9.3.3.2, Figure 9-1
constexpr size_t MAC_ADDRESS_SIZE = 6;
constexpr size_t FC_OFFSET        = 0;  // Frame Control (2 bytes)
constexpr size_t DUR_OFFSET       = 2;  // Duration/ID (2 bytes)
constexpr size_t ADDR1_OFFSET     = 4;  // Address 1 - receiver (6 bytes)
constexpr size_t ADDR2_OFFSET     = 10; // Address 2 - transmitter (6 bytes)
constexpr size_t ADDR3_OFFSET     = 16; // Address 3 - BSSID/SA/DA (6 bytes)
constexpr size_t SEQCTL_OFFSET    = 22; // Sequence Control (2 bytes)

// minimum bytes needed to access each address field
constexpr size_t ADDR1_END = ADDR1_OFFSET + MAC_ADDRESS_SIZE;
constexpr size_t ADDR2_END = ADDR2_OFFSET + MAC_ADDRESS_SIZE;
constexpr size_t ADDR3_END = ADDR3_OFFSET + MAC_ADDRESS_SIZE;

// Frame Type field (FC bits 3-2) - IEEE 802.11-2020, Section 9.2.4.1.3
enum FrameType : uint8_t {
	TYPE_MGMT = 0,
	TYPE_CTRL = 1,
	TYPE_DATA = 2,
	TYPE_EXT  = 3,
};
constexpr uint8_t FC_TYPE_SHIFT    = 2;
constexpr uint8_t FC_TYPE_MASK     = 0x03;
constexpr uint8_t FC_SUBTYPE_SHIFT = 4;
constexpr uint8_t FC_SUBTYPE_MASK  = 0x0F;
// 802.11 management frame header: FC(2)+Dur(2)+Addr1(6)+Addr2(6)+Addr3(6)+SeqCtrl(2)
constexpr size_t  MGMT_HDR_SIZE    = 24;
constexpr uint8_t FC_QOS_BIT       = 0x80; // subtype bit 3 in FC byte 0 — set for QoS subtypes (8-15)
constexpr size_t  QOS_DATA_HDR_SIZE = MGMT_HDR_SIZE + 2; // adds 2-byte QoS-Control field

constexpr uint16_t SEQ_NUM_MOD     = 4096; // 12-bit sequence number field — IEEE 802.11-2020, Section 9.3.2.3
// IEEE 802.11-2020, Table 9-50 — NOTE: incomplete, only values used in this project
enum Status : uint16_t {
	STATUS_SUCCESS = 0,
};
// IEEE 802.11-2020, Table 9-49 — NOTE: incomplete, only values used in this project
enum ReasonCode : uint16_t {
	REASON_CLASS3_FRAME_NONASSOC = 7, // Class 3 frame from nonassociated STA
};
// IEEE 802.11-2020, Table 9-36 — NOTE: incomplete, only values used in this project
enum AuthAlg : uint16_t {
	AUTH_ALG_OPEN = 0, // Open System
	AUTH_ALG_SAE  = 3, // Simultaneous Authentication of Equals
};
// Authentication Transaction Sequence Number — IEEE 802.11-2020, Section 9.3.3.12
enum AuthSeq : uint16_t {
	AUTH_SEQ_REQ  = 1, // request  (STA -> AP)
	AUTH_SEQ_RESP = 2, // response (AP  -> STA)
};

// IEEE 802.11-2020, Table 9-55 — Action frame categories (incomplete)
enum ActionCategory : uint8_t {
	ACTION_CAT_SA_QUERY = 8,
};

// IEEE 802.11-2020, Section 9.6.8 — SA Query Action codes
enum SAQueryAction : uint8_t {
	SA_QUERY_REQUEST  = 0,
	SA_QUERY_RESPONSE = 1,
};

// Authentication frame fixed fields: algorithm(2)+seq(2)+status(2)
constexpr size_t AUTH_FIXED_SIZE = sizeof(AuthAlg) + sizeof(AuthSeq) + sizeof(Status);

// Management frame subtypes (FC bits 7-4, Type=0b00)
enum MgmtSubtype : uint8_t {
	MGMT_ASSOC_REQ     = 0,
	MGMT_ASSOC_RESP    = 1,
	MGMT_REASSOC_REQ   = 2,
	MGMT_REASSOC_RESP  = 3,
	MGMT_PROBE_REQ     = 4,
	MGMT_PROBE_RESP    = 5,
	MGMT_TIMING_ADV    = 6,
	// 7 reserved
	MGMT_BEACON        = 8,
	MGMT_ATIM          = 9,
	MGMT_DISASSOC      = 10,
	MGMT_AUTH          = 11,
	MGMT_DEAUTH        = 12,
	MGMT_ACTION        = 13,
	MGMT_ACTION_NO_ACK = 14,
	// 15 reserved
};

inline constexpr std::array<std::string_view, 16> mgmt_subtype_names = {
	"AssocReq",    "AssocResp",   "ReassocReq",   "ReassocResp",
	"ProbeReq",    "ProbeResp",   "TimingAdv",    "Reserved(7)",
	"Beacon",      "ATIM",        "Disassoc",     "Auth",
	"Deauth",      "Action",      "ActionNoAck",  "Reserved(15)",
};

// Control frame subtypes (FC bits 7-4, Type=0b01)
enum CtrlSubtype : uint8_t {
	// 0-1 reserved
	CTRL_TRIGGER         = 2,
	CTRL_TACK            = 3,
	CTRL_BF_REPORT_POLL  = 4,
	CTRL_NDP_ANNOUNCE    = 5,
	CTRL_EXT             = 6,
	CTRL_WRAPPER         = 7,
	CTRL_BAR             = 8,
	CTRL_BA              = 9,
	CTRL_PS_POLL         = 10,
	CTRL_RTS             = 11,
	CTRL_CTS             = 12,
	CTRL_ACK             = 13,
	CTRL_CF_END          = 14,
	CTRL_CF_END_CF_ACK   = 15,
};

inline constexpr std::array<std::string_view, 16> ctrl_subtype_names = {
	"Reserved(0)", "Reserved(1)", "Trigger",      "TACK",
	"BFReportPoll","NDPAnnounce", "CtrlExt",      "CtrlWrapper",
	"BAR",         "BA",          "PS-Poll",      "RTS",
	"CTS",         "ACK",         "CF-End",       "CF-End+CF-Ack",
};

// Data frame subtypes (FC bits 7-4, Type=0b10)
enum DataSubtype : uint8_t {
	DATA                     = 0,
	DATA_CF_ACK              = 1,
	DATA_CF_POLL             = 2,
	DATA_CF_ACK_POLL         = 3,
	DATA_NULL                = 4,
	CF_ACK                   = 5,
	CF_POLL                  = 6,
	CF_ACK_POLL              = 7,
	QOS_DATA                 = 8,
	QOS_DATA_CF_ACK          = 9,
	QOS_DATA_CF_POLL         = 10,
	QOS_DATA_CF_ACK_POLL     = 11,
	QOS_NULL                 = 12,
	// 13 reserved
	QOS_CF_POLL              = 14,
	QOS_CF_ACK_POLL          = 15,
};

inline constexpr std::array<std::string_view, 16> data_subtype_names = {
	"Data",      "Data+CF-Ack",          "Data+CF-Poll",         "Data+CF-Ack+CF-Poll",
	"Null",      "CF-Ack",               "CF-Poll",              "CF-Ack+CF-Poll",
	"QoS-Data",  "QoS-Data+CF-Ack",      "QoS-Data+CF-Poll",     "QoS-Data+CF-Ack+CF-Poll",
	"QoS-Null",  "Reserved(13)",         "QoS-CF-Poll",          "QoS-CF-Ack+CF-Poll",
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

inline std::string_view to_string(const uint8_t type, const uint8_t subtype) {
	if(subtype >= 16) return "<invalid subtype>";
	if(type == TYPE_MGMT) return mgmt_subtype_names[subtype];
	if(type == TYPE_CTRL) return ctrl_subtype_names[subtype];
	if(type == TYPE_DATA) return data_subtype_names[subtype];
	return "<invalid type>";
}
inline std::string_view to_string(const MgmtSubtype s) { return mgmt_subtype_names[s]; }
inline std::string_view to_string(const CtrlSubtype s) { return ctrl_subtype_names[s]; }
inline std::string_view to_string(const DataSubtype s) { return data_subtype_names[s]; }

inline std::string_view ie_to_string(const IE tag) {
	const auto it = ie_names.find(tag);
	return it != ie_names.end() ? it->second : "<unknown IE>";
}
inline std::string_view ie_to_string(uint8_t tag) { return ie_to_string(static_cast<IE>(tag)); }

}
