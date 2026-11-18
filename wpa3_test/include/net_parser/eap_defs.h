#pragma once
#include <cstdint>
#include <map>
#include <string_view>

namespace wpa3_tester::eap {

// IEEE 802.1X-2020, Section 11.3 — EtherType for EAPOL (assigned by IEEE Registration Authority)
constexpr uint16_t ETHERTYPE_EAPOL    = 0x888E;
constexpr uint8_t  ETHERTYPE_EAPOL_HI = 0x88;
constexpr uint8_t  ETHERTYPE_EAPOL_LO = 0x8E;

// EAPOL packet types (IEEE 802.1X-2020, Section 11.3)
enum EapolType : uint8_t {
	EAPOL_EAP    = 0,
	EAPOL_START  = 1,
	EAPOL_LOGOFF = 2,
	EAPOL_KEY    = 3,
};

// EAP codes (RFC 3748, section 4)
enum EapCode : uint8_t {
	CODE_REQUEST  = 1,
	CODE_RESPONSE = 2,
	CODE_SUCCESS  = 3,
	CODE_FAILURE  = 4,
};

// EAP type numbers (IANA)
enum EapType : uint8_t {
	TYPE_IDENTITY  = 1,
	TYPE_MD5       = 4,
	TYPE_GTC       = 6,
	TYPE_TLS       = 13,
	TYPE_LEAP      = 17,
	TYPE_SIM       = 18,
	TYPE_TTLS      = 21,
	TYPE_AKA       = 23,
	TYPE_PEAP      = 25,
	TYPE_MSCHAPV2  = 26,
	TYPE_POTP      = 29,
	TYPE_FAST      = 33,
	TYPE_EKE       = 40,
	TYPE_TEAP      = 43,
	TYPE_AKA_PRIME = 50,
	TYPE_PWD       = 52,
	TYPE_EXPANDED  = 254,
};

// EAP-PWD opcodes (RFC 5931, section 3.1, PWD-Exch)
enum PwdOpcode : uint8_t {
	PWD_OPCODE_ID      = 1,
	PWD_OPCODE_COMMIT  = 2,
	PWD_OPCODE_CONFIRM = 3,
};

inline const std::map<EapolType, std::string_view> eapol_type_names = {
	{EAPOL_EAP,    "EAP"},
	{EAPOL_START,  "EAPOL-Start"},
	{EAPOL_LOGOFF, "EAPOL-Logoff"},
	{EAPOL_KEY,    "EAPOL-Key"},
};

inline const std::map<EapCode, std::string_view> eap_code_names = {
	{CODE_REQUEST,  "Request"},
	{CODE_RESPONSE, "Response"},
	{CODE_SUCCESS,  "Success"},
	{CODE_FAILURE,  "Failure"},
};

inline const std::map<EapType, std::string_view> eap_type_names = {
	{TYPE_IDENTITY,  "Identity"},
	{TYPE_MD5,       "MD5"},
	{TYPE_GTC,       "GTC"},
	{TYPE_TLS,       "TLS"},
	{TYPE_LEAP,      "LEAP"},
	{TYPE_SIM,       "SIM"},
	{TYPE_TTLS,      "TTLS"},
	{TYPE_AKA,       "AKA"},
	{TYPE_PEAP,      "PEAP"},
	{TYPE_MSCHAPV2,  "MSCHAPv2"},
	{TYPE_POTP,      "POTP"},
	{TYPE_FAST,      "FAST"},
	{TYPE_EKE,       "EKE"},
	{TYPE_TEAP,      "TEAP"},
	{TYPE_AKA_PRIME, "AKA'"},
	{TYPE_PWD,       "PWD"},
	{TYPE_EXPANDED,  "Expanded"},
};

// to_string — returns "<invalid …>" for unknown values; callers format fallback if needed
inline std::string_view to_string(EapolType v) {
	const auto it = eapol_type_names.find(v);
	return it != eapol_type_names.end() ? it->second : "<invalid EapolType>";
}
inline std::string_view to_string(const EapCode v) {
	const auto it = eap_code_names.find(v);
	return it != eap_code_names.end() ? it->second : "<invalid EapCode>";
}
inline std::string_view to_string(const EapType v) {
	const auto it = eap_type_names.find(v);
	return it != eap_type_names.end() ? it->second : "<invalid EapType>";
}

// EAPOL-Key frame: field offsets from start of EAPOL body (byte after 0x888E ethertype)
// IEEE 802.1X-2020, Section 11.9; IEEE 802.11-2020, Section 12.7.2
constexpr uint8_t EAPOL_KEY_OFF_TYPE  = 1; // EAPOL packet type (must equal EAPOL_KEY=3)
constexpr uint8_t EAPOL_KEY_OFF_KI_HI = 5; // Key Information high byte (bits 15-8)
constexpr uint8_t EAPOL_KEY_OFF_KI_LO = 6; // Key Information low byte  (bits  7-0)
constexpr uint8_t EAPOL_KEY_MIN_SIZE  = 7; // bytes needed to read key info

// Key Information field bit masks — IEEE 802.11-2020, Section 12.7.2, Table 12-7
// Stored big-endian; KI_HI = byte[5], KI_LO = byte[6] relative to EAPOL body
constexpr uint8_t KI_HI_MIC    = 0x01; // bit  8: Key MIC
constexpr uint8_t KI_HI_SECURE = 0x02; // bit  9: Secure
constexpr uint8_t KI_LO_TYPE   = 0x08; // bit  3: Key Type (1=pairwise PTK, 0=group GTK)
constexpr uint8_t KI_LO_INSTALL = 0x40; // bit  6: Install
constexpr uint8_t KI_LO_ACK    = 0x80; // bit  7: Key ACK

// 4-way / group key handshake message number (derived from key_info bits)
enum class EapolMsg { Unknown = -1, Group = 0, Msg1 = 1, Msg2 = 2, Msg3 = 3, Msg4 = 4 };

inline const std::map<EapolMsg, std::string_view> eapol_msg_labels = {
	{EapolMsg::Group, "EAPOL Group Key"},
	{EapolMsg::Msg1,  "EAPOL 1/4"},
	{EapolMsg::Msg2,  "EAPOL 2/4"},
	{EapolMsg::Msg3,  "EAPOL 3/4"},
	{EapolMsg::Msg4,  "EAPOL 4/4"},
};

inline std::string_view to_string(EapolMsg v) {
	const auto it = eapol_msg_labels.find(v);
	return it != eapol_msg_labels.end() ? it->second : "<unknown EapolMsg>";
}

}
