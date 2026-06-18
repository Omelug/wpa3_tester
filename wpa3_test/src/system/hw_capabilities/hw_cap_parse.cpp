#include <cstdio>
#include <random>
#include <string>
#include "config/RunStatus.h"
#include "logger/error_log.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester{
using namespace std;
using namespace filesystem;
using namespace Tins;

int hw_capabilities::freq_to_channel(const int freq){
	// 2.4 GHz
	if(freq == 2484) return 14;
	if(freq >= 2412 && freq <= 2472){
		const int ch = (freq - 2407) / 5;
		if((freq - 2407) % 5 == 0) return ch;
	}

	// 5 GHz
	if(freq >= 5180 && freq <= 5885){
		const int ch = (freq - 5000) / 5;
		if((freq - 5000) % 5 == 0) return ch;
	}

	// 6 GHz
	if(freq >= 5955 && freq <= 7115){
		const int ch = (freq - 5950) / 5;
		if((freq - 5950) % 5 == 0) return ch;
	}

	throw invalid_argument("Invalid frequency: " + to_string(freq) + " MHz");
}

int hw_capabilities::channel_to_freq(const Channel &ch){
	// 2.4 GHz
	if(ch.band == WifiBand::BAND_2_4 || ch.band == WifiBand::BAND_2_4_or_5){
		if(ch.ch_num == 14) return 2484;
		if(ch.ch_num >= 1 && ch.ch_num <= 13) return 2407 + ch.ch_num * 5;
	}
	// 5 GHz
	if(ch.band == WifiBand::BAND_5 || ch.band == WifiBand::BAND_2_4_or_5){
		if(ch.ch_num >= 36 && ch.ch_num <= 177){
			if((ch.ch_num - 36) % 4 == 0 || ch.ch_num == 177) return 5000 + ch.ch_num * 5;
		}
	}

	// 6 GHz
	if(ch.band == WifiBand::BAND_6){
		if(ch.ch_num >= 1 && ch.ch_num <= 233){
			const int freq = 5950 + ch.ch_num * 5;
			if(freq >= 5955 && freq <= 7115) return freq;
		}
	}
	throw invalid_argument("Invalid channel: " + to_string(ch.ch_num));
}

HWAddress<6> hw_capabilities::rand_mac(){
	static random_device rd;
	static mt19937 gen(rd());
	uniform_int_distribution<> dis(0, 255);

	char mac[18];
	snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x", dis(gen), dis(gen), dis(gen), dis(gen), dis(gen),
			dis(gen));
	return HWAddress<6>(mac);
}
}