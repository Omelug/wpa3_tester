#pragma once
#include <string>
#include <tins/tins.h>
#include "logger/log.h"
#include "system/utils.h"
#include "system/wifi_channel.h"

namespace wpa3_tester {
struct NetworkConfig {
	std::string ssid;
	Channel real_channel = {};
	Channel rogue_channel = {};
};

class ClientState {
public:
	enum State {
		Unknown = -1,
		Target = 0,
		// target send frame to disconnected
		// tester don't know channel because forwarding can catch fake frames
		Target_disconnected,
		// tester send CSA frames to move
		Sent_to_rogue,
		// Probe requests in Drogue channel
		Finding,
		// Auth on rogue channel
		Authenticated,
		// Assoc on rogue channel
		Associated,
		// EAPOl 4 found on rogue chanel
		GotMitm
	};
protected:
	State state = Unknown;
	Tins::HWAddress<6> macaddr;
	std::optional<std::filesystem::path> log_folder;
	using time_point = std::chrono::steady_clock::time_point;
	time_point last_real = std::chrono::steady_clock::now();
	time_point last_rogue = std::chrono::steady_clock::now();
public:
	virtual ~ClientState() = default;

	[[nodiscard]] Tins::HWAddress<6> get_mac() const { return macaddr; }
	[[nodiscard]] State get_state() const { return state; }

	explicit ClientState(const Tins::HWAddress<6> &mac, std::optional<std::filesystem::path> log_folder = std::nullopt):
		macaddr(mac),
		log_folder(std::move(log_folder)) {}

	explicit ClientState(const Tins::HWAddress<6> mac, const State state,
			const std::optional<std::filesystem::path> &log_folder = std::nullopt):
		state(state),
		macaddr(mac),
		log_folder(log_folder) {}

	void update_state(const State s) {
		log(LogLevel::DEBUG, "Client {} moved to state {}", macaddr, state2str(s));
		if(log_folder) {
			const auto path = *log_folder / (macaddr.to_string() + "_state.log");
			const bool is_new = !std::filesystem::exists(path);
			if(std::ofstream f(path, std::ios::app); f) {
				if(is_new) set_public_perms(path);
				std::stringstream ss;
				ss << current_timestamp();
				ss << " [STATE] " << macaddr << " : ";
				ss << state2str(state) << " -> " << state2str(s);
				f << ss.str();
				log(LogLevel::INFO, ss.str());
			}
		}
		state = s;
	}

	[[nodiscard]] bool is_state(const State s) const { return this->state == s; }

	static std::string state2str(const State state) {
		static const std::string names[] = { "Unknown",
			"Target",
			"Target_disconnected",
			"Sent_to_rogue",
			"Finding",
			"Authenticated",
			"Associated",
			"GotMitm" };
		const int idx = static_cast<int>(state) + 1; // Unknown=-1 maps to index 0
		if(idx < 0 || idx >= static_cast<int>(std::size(names))) return "Invalid";
		return names[idx];
	}
};
}