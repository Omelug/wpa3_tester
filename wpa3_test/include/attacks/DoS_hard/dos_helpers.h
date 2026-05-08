#pragma once
#include <chrono>
#include <cstdint>
#include <thread>
#include <vector>
#include <tins/tins.h>
#include "logger/log.h"

namespace wpa3_tester::dos_helpers{

template<typename FrameGen>
void timed_burst(Tins::PacketSender &sender, const int attack_time_sec,
				 const size_t burst_size, const size_t packets_per_second_limit,
				 FrameGen &&frame_gen
){
	long long counter = 0;
	long long next_log = 0;
	const auto end_time = std::chrono::steady_clock::now() + std::chrono::seconds(attack_time_sec);

	while(std::chrono::steady_clock::now() < end_time){
		const auto burst_start = std::chrono::steady_clock::now();
		auto frame = frame_gen();
		if(!frame) continue;

		for(size_t i = 0; i < burst_size; ++i) sender.send(*frame);

		const auto target = std::chrono::microseconds(burst_size * 1'000'000 / packets_per_second_limit);
		if(const auto elapsed = std::chrono::steady_clock::now() - burst_start; elapsed < target)
			std::this_thread::sleep_for(target - elapsed);

		counter += static_cast<long long>(burst_size);
		if(counter >= next_log){
			log(LogLevel::DEBUG, "Packets sent: {}", counter);
			next_log += 10 * static_cast<long long>(burst_size);
		}
	}
	log(LogLevel::INFO, "Done. Total packets sent: {}", counter);
}


std::string bytes_to_hex(const std::vector<uint8_t> &bytes);
std::string bytes_to_hex_plain(const std::vector<uint8_t> &bytes);

struct SAEPair{
	uint16_t status = 0;
	mutable uint16_t group_id = 19;
	std::vector<uint8_t> token;
	std::vector<uint8_t> scalar;
	std::vector<uint8_t> element;

	bool is_valid() const{
		switch(status){
		case 0:
		case 126: return !scalar.empty() && !element.empty();
		case 76: return !token.empty();
		case 77: return group_id != 0;
		default: return false;
		}
	}

	std::string to_str() const{
		return "SAEPair {\n" "  status:   " + std::to_string(status) + "\n" "  group_id: " + std::to_string(group_id) +
				"\n" "  valid:    " + (is_valid() ? "true" : "false") + "\n" "  scalar  (" +
				std::to_string(scalar.size()) + " bytes): " + bytes_to_hex(scalar) + "\n" "  element (" +
				std::to_string(element.size()) + " bytes): " + bytes_to_hex(element) + "\n" "  token   (" +
				std::to_string(token.size()) + " bytes): " + bytes_to_hex(token) + "\n" "}";
	}
};

bool check_fcs_present(const std::vector<uint8_t> &packet);
std::optional<SAEPair> parse_sae_commit(const std::vector<uint8_t> &frame_rt);
Tins::RadioTap make_sae_commit(const Tins::HWAddress<6> &ap_mac, const Tins::HWAddress<6> &sta_mac,
								const SAEPair &sae_params
);
}