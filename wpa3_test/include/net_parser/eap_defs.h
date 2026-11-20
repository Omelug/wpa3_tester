#pragma once
#include <cstdint>
#include <map>
#include <string_view>

namespace wpa3_tester::eap {

// IEEE 802.1X-2020, Section 11.3 - EtherType for EAPOL (assigned by IEEE Registration Authority)
constexpr uint16_t ETHERTYPE_EAPOL    = 0x888E;
constexpr uint8_t  ETHERTYPE_EAPOL_HI = 0x88;
constexpr uint8_t  ETHERTYPE_EAPOL_LO = 0x8E;

constexpr uint8_t EAPOL_VERSION = 1; // IEEE 802.1X-2020, Section 11.3

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

// EAP type numbers (IANA) - NOTE: incomplete, only types used in this project
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

// to_string - returns "<invalid …>" for unknown values; callers format fallback if needed
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

// EAP body offsets within a serialized EAPOL frame (IEEE 802.1X-2020, Section 11.3; RFC 3748, Section 4)
// EAPOL header: version(1) + type(1) + length(2) = 4 bytes; EAP body follows immediately
constexpr uint8_t EAPOL_HDR_SIZE  = 4;
constexpr uint8_t EAPOL_TYPE_OFF  = 1; // EAPOL type byte (version=0, type=1, len=2-3)
constexpr uint8_t EAPOL_LEN_OFF   = 2; // EAPOL body length (big-endian uint16)
constexpr uint8_t EAP_HDR_SIZE    = 4;                             // code(1)+id(1)+length(2)
constexpr uint8_t EAP_CODE_OFF    = EAPOL_HDR_SIZE;                // = 4: EAP Code (1 byte)
constexpr uint8_t EAP_TYPE_OFF    = EAPOL_HDR_SIZE + EAP_HDR_SIZE; // = 8: EAP Type (1 byte, Req/Resp only)
constexpr uint8_t PWD_EXCH_OFF    = EAP_TYPE_OFF + 1;              // offset of PWD-Exch byte
constexpr uint8_t PWD_DATA_OFF    = PWD_EXCH_OFF + 1;              // offset of PWD payload
constexpr uint8_t PWD_OPCODE_MASK = 0x3F; // lower 6 bits of PWD-Exch byte (RFC 5931, Section 3.1)
constexpr uint8_t PWD_L_BIT       = 7;    // L-bit position in PWD-Exch byte (length-included flag)
constexpr size_t  PWD_ID_PREFIX   = 9;    // PWD-ID fixed prefix: Group(2)+RF(1)+PRF(1)+Token(4)+Prep(1)
// LLC+SNAP encapsulation for EAPOL-over-802.11 (IEEE 802.1H / RFC 1042)
constexpr uint8_t LLC_SNAP_DSAP  = 0xAA;
constexpr uint8_t LLC_SNAP_CTRL  = 0x03; // Unnumbered Information
constexpr size_t  LLC_SNAP_SIZE  = 8;    // LLC(3) + OUI(3) + EtherType(2)
constexpr size_t  SNAP_ETYPE_OFF = 6;    // EtherType offset within LLC+SNAP block

// EAPOL-Key frame: field offsets from start of EAPOL body (byte after 0x888E ethertype)
// IEEE 802.1X-2020, Section 11.9; IEEE 802.11-2024, Section 12.7.2, Figure 12-35
constexpr uint8_t EAPOL_KEY_OFF_TYPE  = 1; // EAPOL packet type (must equal EAPOL_KEY=3)
constexpr uint8_t EAPOL_KEY_OFF_KI_HI = 5; // Key Information high byte (bits 15-8)
constexpr uint8_t EAPOL_KEY_OFF_KI_LO = 6; // Key Information low byte  (bits  7-0)
constexpr uint8_t EAPOL_KEY_MIN_SIZE  = 7; // bytes needed to read key info
// offsets below assume standard 16-byte MIC (non-AEAD AKMs; IEEE 802.11-2024, Table 12-11)
// layout: HDR(4)+DescType(1)+KI(2)+KeyLen(2)+ReplayCounter(8)+Nonce(32)+IV(16)+RSC(8)+Rsvd(8)+MIC(16)
constexpr size_t EAPOL_KEY_MIC_SIZE   = 16;
constexpr size_t EAPOL_KEY_OFF_KD_LEN = 97; // Key Data Length field (2 bytes, big-endian)
constexpr size_t EAPOL_KEY_OFF_KD     = 99; // Key Data field start

// Key Information field bit masks - IEEE 802.11-2020, Section 12.7.2, Table 12-7
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
