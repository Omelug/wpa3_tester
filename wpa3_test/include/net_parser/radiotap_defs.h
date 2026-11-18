#pragma once
#include <array>
#include <endian.h>
#include <map>
#include <radiotap.h>
#include <radiotap_iter.h>
#include <string_view>
#include <vector>

// String maps and to_string helpers for radiotap fields.
// Source: https://www.radiotap.org/fields/defined
namespace wpa3_tester::radiotap {

inline const std::map<int, std::string_view> field_names = {
	{IEEE80211_RADIOTAP_TSFT,             "TSFT"},
	{IEEE80211_RADIOTAP_FLAGS,            "Flags"},
	{IEEE80211_RADIOTAP_RATE,             "Rate"},
	{IEEE80211_RADIOTAP_CHANNEL,          "Channel"},
	{IEEE80211_RADIOTAP_FHSS,             "FHSS"},
	{IEEE80211_RADIOTAP_DBM_ANTSIGNAL,    "dBm AntennaSignal"},
	{IEEE80211_RADIOTAP_DBM_ANTNOISE,     "dBm AntennaNoise"},
	{IEEE80211_RADIOTAP_LOCK_QUALITY,     "LockQuality"},
	{IEEE80211_RADIOTAP_TX_ATTENUATION,   "TxAttenuation"},
	{IEEE80211_RADIOTAP_DB_TX_ATTENUATION,"dB TxAttenuation"},
	{IEEE80211_RADIOTAP_DBM_TX_POWER,     "dBm TxPower"},
	{IEEE80211_RADIOTAP_ANTENNA,          "Antenna"},
	{IEEE80211_RADIOTAP_DB_ANTSIGNAL,     "dB AntennaSignal"},
	{IEEE80211_RADIOTAP_DB_ANTNOISE,      "dB AntennaNoise"},
	{IEEE80211_RADIOTAP_RX_FLAGS,         "RxFlags"},
	{IEEE80211_RADIOTAP_TX_FLAGS,         "TxFlags"},
	{IEEE80211_RADIOTAP_RTS_RETRIES,      "RtsRetries"},
	{IEEE80211_RADIOTAP_DATA_RETRIES,     "DataRetries"},
	{IEEE80211_RADIOTAP_MCS,              "MCS"},
	{IEEE80211_RADIOTAP_AMPDU_STATUS,     "A-MPDU Status"},
	{IEEE80211_RADIOTAP_VHT,              "VHT"},
	{IEEE80211_RADIOTAP_TIMESTAMP,        "Timestamp"},
};

inline std::string_view to_string(int field_id) {
	const auto it = field_names.find(field_id);
	return it != field_names.end() ? it->second : "<invalid radiotap field>";
}

// TX flags for injection (https://www.radiotap.org/fields/TX%20flags.html)
constexpr uint16_t TX_NOACK   = 0x0008; // don't wait for ACK
constexpr uint16_t TX_NOSEQ   = 0x0010; // preserve sequence number (kernel >= 5.9)
constexpr uint16_t TX_ORDER   = 0x0020; // don't reorder relative to other injected frames
constexpr uint16_t TX_DEFAULT = TX_NOACK | TX_ORDER;

// Minimal radiotap header for injection - FLAGS field only (no FCS, FRAG+DATAPAD set).
// it_len=9: 8-byte ieee80211_radiotap_header struct + 1-byte Flags field value.
// it_present bit 1 (IEEE80211_RADIOTAP_FLAGS) set; Flags=FRAG|DATAPAD.
inline constexpr std::array<uint8_t, 9> MINIMAL_INJECT_HDR = {
	PKTHDR_RADIOTAP_VERSION, 0x00,                                       // it_version, it_pad
	0x09, 0x00,                                                          // it_len = 9 (LE)
	static_cast<uint8_t>(1u << IEEE80211_RADIOTAP_FLAGS), 0x00, 0x00, 0x00,          // it_present: FLAGS bit
	static_cast<uint8_t>(IEEE80211_RADIOTAP_F_FRAG | IEEE80211_RADIOTAP_F_DATAPAD),  // Flags field value
};

// Returns the radiotap header length from raw frame bytes (little-endian it_len at offset 2).
// Returns 0 if raw is too short to hold a radiotap header.
inline uint16_t get_rt_len(const std::vector<uint8_t> &raw) {
	if(raw.size() < sizeof(ieee80211_radiotap_header)) return 0;
	return le16toh(reinterpret_cast<const ieee80211_radiotap_header *>(raw.data())->it_len);
}

}
