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

std::vector<Tins::HWAddress<6>> get_connected_stas(RunStatus &rs);
bool check_fcs_present(const std::vector<uint8_t> &packet);

}