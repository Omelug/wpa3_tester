#pragma once
#include <string>
#include "config/RunStatus.h"

namespace wpa3_tester::bl0ck_attack{
struct Bl0ckResult{
	//std::optional<bool> passed;
	int disconnect_count = 0;
	std::optional<bool> ap_disconnected;
	std::vector<double> reconnect_times_ms;
};

// Send a burst of bl0ck frames (BAR or BA)
Tins::RadioTap get_bl0ck_frame(const Tins::HWAddress<6> &ap_hw, const Tins::HWAddress<6> &sta_hw, int subtype);

// Send BAR or BA frames for the specified duration
void block(const Tins::HWAddress<6> &sta_mac, const Tins::HWAddress<6> &ap_mac, const std::string &iface,
			int frame_in_batch, const std::string &attack_type, int duration_sec, bool is_random
);

void setup_attack(RunStatus & rs);
void run_bl0ck_attack(RunStatus & rs);

void stats_bl0ck_attack(const RunStatus &rs);
void generate_report(const RunStatus &rs, const Bl0ckResult &result, const std::filesystem::path &attacker_graph,
					const std::filesystem::path &client_graph, const std::filesystem::path &ap_graph
);
void speed_observation_start(RunStatus & rs);

Tins::RadioTap get_BAR_frame(const Tins::HWAddress<6> &ap_mac, const Tins::HWAddress<6> &sta_mac, uint8_t fn = 4,
							uint16_t sn = 1175
);
Tins::RadioTap get_BA_frame(const Tins::HWAddress<6> &ap_mac, const Tins::HWAddress<6> &sta_mac);

Tins::RadioTap get_BARS_frame(const Tins::HWAddress<6> &ap_hw, const Tins::HWAddress<6> &sta_hw,
							const std::string &iface, int timeout_sec = 30
);
}