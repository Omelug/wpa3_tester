#pragma once
#include <string>
#include <tins/tins.h>
#include "wifi_util.h"
#include "logger/log.h"

namespace wpa3_tester{
struct NetworkConfig{
	std::string ssid;
	uint8_t real_channel = -1;
	uint8_t rogue_channel = -1;
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
	using time_point = std::chrono::steady_clock::time_point;
	time_point last_real = std::chrono::steady_clock::now();
	time_point last_rogue = std::chrono::steady_clock::now();
public:
	virtual ~ClientState() = default;

	Tins::HWAddress<6> get_mac() const{ return macaddr; }
	State get_state() const{ return state; }

	explicit ClientState(const Tins::HWAddress<6> &mac): macaddr(mac){}
	explicit ClientState(const Tins::HWAddress<6> mac, const State state): state(state), macaddr(mac){}

	void update_state(const State s){
		log(LogLevel::DEBUG, "Client {} moved to state {}", macaddr.to_string(), state2str(s));
		state = s;
	}

	bool is_state(const State s) const{ return this->state == s; }

	// By default, everything is forwarded.
	virtual bool should_forward(const Tins::PDU & /*pkt*/) const{ return true; }
	// By default, frames are not modified.
	virtual void modify_packet(Tins::PDU &/*pkt*/) const{}
protected:
	static std::string state2str(const State state){
		static const char *names[] = {
			"Unknown", "Target", "Sent_to_rogue", "Finding", "Authenticated", "Associated", "GotMitm"
		};
		return names[state];
	}
};
}