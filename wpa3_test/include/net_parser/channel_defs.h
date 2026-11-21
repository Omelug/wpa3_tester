#pragma once
#include <array>
#include <cstdint>
#include "system/wifi_channel.h"
// IEEE 802.11-2024 channel utilities shared between CSA and other components.
namespace wpa3_tester::dot11 {
// Valid channel number ranges per band - IEEE 802.11-2024, Annex E
constexpr uint8_t CH_2_4_MIN =   1; constexpr uint8_t CH_2_4_MAX =  14;
constexpr uint8_t CH_5_MIN_1 =  36; constexpr uint8_t CH_5_MAX_1 =  48;
constexpr uint8_t CH_5_MIN_2 =  52; constexpr uint8_t CH_5_MAX_2 = 144;
constexpr uint8_t CH_5_MIN_3 = 149; constexpr uint8_t CH_5_MAX_3 = 165;
constexpr uint8_t CH_6_MIN   =   1; constexpr uint8_t CH_6_MAX   = 233;
// Map 5 GHz primary channel -> VHT 80 MHz center channel.
// IEEE 802.11-2024, Table E-4 (20/80 MHz channel groups, 5 GHz band only).
inline uint8_t vht_center_ch(const uint8_t ch) {
	static constexpr std::array<std::pair<uint8_t, uint8_t>, 6> groups{{
		{ 36, 42 }, { 52, 58 }, { 100, 106 }, { 116, 122 }, { 132, 138 }, { 149, 155 }
	}};
	for(auto [base, center] : groups)
		if(ch >= base && ch < base + 16) return center;
	return ch;
}
// Global Operating Class for a 20 MHz channel - IEEE 802.11-2024, Table E-4 (incomplete).
inline uint8_t get_operating_class(const Channel &ch) {
	if(ch.band == WifiBand::BAND_2_4) return 81;
	const uint8_t n = ch.ch_num;
	if(n >= 36  && n <= 48)  return 115;
	if(n >= 52  && n <= 64)  return 118;
	if(n >= 100 && n <= 140) return 121;
	if(n >= 149 && n <= 169) return 124;
	return n > 14 ? 115 : 81;
}
}
