#pragma once
#include <cstdint>
#include <string>
#include <tins/tins.h>
#include "config/RunStatus.h"
#include "system/wifi_channel.h"

namespace wpa3_tester{
int get_channel(const std::string &iface);

int chan2freq(Channel ch);

std::string get_ssid(const Tins::Dot11Beacon &beacon);

struct Dot11Addrs{
	Tins::HWAddress<6> addr1;
	Tins::HWAddress<6> addr2;
};

Dot11Addrs get_addrs(const Tins::PDU &pdu, const std::vector<uint8_t> &raw);
Tins::Dot11ProbeResponse beacon_to_probe_resp(const Tins::Dot11Beacon &beacon, const Channel &rogue_channel);
Tins::Dot11AssocResponse *assoc_resp_channel_patch(const Tins::Dot11AssocResponse &assoc, const Channel &rogue_channel);
bool is_eapol(const Tins::PDU &pdu);
int get_eapol_msg_num(const Tins::PDU &pdu);
Tins::Dot11Beacon append_csa(const Tins::Dot11Beacon &beacon, const Channel &channel, uint8_t count = 1);

// EAPOL helpers
uint64_t get_eapol_replay_num(const Tins::Dot11Data &pkt);

void start_ap(RunStatus &rs, const std::string &ap_iface, const ActorPtr &base_actor, Channel channel,
			const Tins::Dot11Beacon &beacon, std::optional<Tins::HWAddress<6>> mac = std::nullopt, int interval = 100,
			int dtim_period = 1
);
void stop_ap(const std::string &iface, const std::optional<std::string> &netns);
}