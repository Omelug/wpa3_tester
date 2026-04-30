#pragma once
#include <string>
#include <cstdint>
#include <tins/tins.h>
#include "config/RunStatus.h"

namespace wpa3_tester{
int get_channel(const std::string &iface);

int chan2freq(int channel);

std::string get_ssid(const Tins::Dot11Beacon &beacon);

struct Dot11Addrs {
    Tins::HWAddress<6> addr1;
    Tins::HWAddress<6> addr2;
};
Dot11Addrs get_addrs(const Tins::PDU &pdu, const std::vector<uint8_t> &raw);
Tins::Dot11ProbeResponse beacon_to_probe_resp(const Tins::Dot11Beacon &beacon, int rogue_channel);
Tins::Dot11AssocResponse *assoc_resp_channel_patch(const Tins::Dot11AssocResponse &assoc, int rogue_channel);
int get_eapol_msg_num(const Tins::PDU& pdu);
Tins::Dot11Beacon append_csa(const Tins::Dot11Beacon &beacon, uint8_t channel, uint8_t count = 1);

// EAPOL helpers
uint64_t get_eapol_replay_num(const Tins::Dot11Data &pkt);

void start_ap(RunStatus &rs, const std::string &ap_iface, const ActorPtr &base_actor, int channel,
              const Tins::Dot11Beacon &beacon, std::optional<std::string> mac = std::nullopt,
              int interval = 100, int dtim_period = 1
);
void stop_ap(const std::string &iface, const std::optional<std::string> &netns);
}