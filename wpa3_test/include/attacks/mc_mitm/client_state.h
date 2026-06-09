#pragma once
#include <string>
#include <tins/tins.h>
#include "logger/log.h"
#include "system/wifi_channel.h"

namespace wpa3_tester{
struct NetworkConfig{
	std::string ssid;
	Channel real_channel = {};
	Channel rogue_channel = {};
};

class ClientState{
public:
	enum State{
		Unknown = -1,
		Target  = 0,
		Sent_to_rogue,
		Finding,
		Authenticated,
		Associated,
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

	Tins::HWAddress<6> get_mac() const{ return macaddr; }
	State get_state() const{ return state; }

	explicit ClientState(const Tins::HWAddress<6> &mac, std::optional<std::filesystem::path> log_folder = std::nullopt): macaddr(mac), log_folder(std::move(log_folder)){}
	explicit ClientState(const Tins::HWAddress<6> mac, const State state, const std::optional<std::filesystem::path> &log_folder = std::nullopt): state(state), macaddr(mac), log_folder(std::move(log_folder)){}

	void update_state(const State s){
		log(LogLevel::DEBUG, "Client {} moved to state {}", macaddr.to_string(), state2str(s));
		if(log_folder){
			const auto path = *log_folder / (macaddr.to_string() + "_state.log");
			if(std::ofstream f(path, std::ios::app); f)
				f << "[STATE] " << macaddr <<" : " << state2str(state) << " -> " << state2str(s) << std::endl;
		}
		state = s;
	}

	bool is_state(const State s) const{ return this->state == s; }

	// By default, everything is forwarded.
	virtual bool should_forward(const Tins::PDU &) const{ return true; }
	// By default, frames are not modified.
	virtual void modify_packet(Tins::PDU &) const{}
protected:
	static std::string state2str(const State state){
		static const char *names[] = {
			"Unknown", "Target", "Sent_to_rogue", "Finding", "Authenticated", "Associated", "GotMitm"
		};
		return names[state];
	}
};
}