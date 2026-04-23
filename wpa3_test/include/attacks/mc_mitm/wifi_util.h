#pragma once
#include <string>
#include <cstdint>
#include <vector>
#include <tins/tins.h>
#include "config/RunStatus.h"

int  get_channel(const std::string& iface);

int chan2freq(int channel);

std::string get_ssid(const Tins::Dot11Beacon& beacon);

Tins::Dot11ProbeResponse beacon_to_probe_resp(const Tins::Dot11Beacon &beacon, int rogue_channel);
Tins::Dot11Beacon* beacon_channel_patch(const Tins::Dot11Beacon& beacon, int rogue_channel);
Tins::Dot11AssocResponse* assoc_resp_channel_patch(const Tins::Dot11AssocResponse& assoc, int rogue_channel);
Tins::Dot11Beacon append_csa(const Tins::Dot11Beacon& beacon, uint8_t channel, uint8_t count = 1);

// EAPOL helpers
int  get_eapol_msg_num(const Tins::Dot11Data& pkt);
uint64_t get_eapol_replay_num(const Tins::Dot11Data& pkt);

void start_ap(wpa3_tester::RunStatus& rs, const std::string& ap_iface, const std::string& base_iface, int channel,
              const Tins::Dot11Beacon& beacon,
              int interval = 100, int dtim_period = 1);
void stop_ap(const std::string& iface);