#pragma once

namespace wpa3_tester{
enum class WifiBand{
	BAND_2_4_or_5,
	BAND_2_4,
	BAND_5,
	BAND_6
};

struct Channel{
	int ch_num = 0;
	WifiBand band = WifiBand::BAND_2_4_or_5;
	std::optional<std::string> ht_mode;
};
}
