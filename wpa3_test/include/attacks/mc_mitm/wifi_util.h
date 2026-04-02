#pragma once
#include <string>
#include <cstdint>
#include <vector>
#include <tins/tins.h>

// 802.11 Information Element type IDs
constexpr uint8_t IEEE_TLV_TYPE_SSID    = 0;
constexpr uint8_t IEEE_TLV_TYPE_CHANNEL = 3;
constexpr uint8_t IEEE_TLV_TYPE_TIM     = 5;
constexpr uint8_t IEEE_TLV_TYPE_RSN     = 48;
constexpr uint8_t IEEE_TLV_TYPE_CSA     = 37;
constexpr uint8_t IEEE_TLV_TYPE_FT      = 55;
constexpr uint8_t IEEE_TLV_TYPE_VENDOR  = 221;

// EAPOL key info flags (big-endian bit positions)
constexpr uint16_t EAPOL_FLAG_PAIRWISE = 0b0000001000;
constexpr uint16_t EAPOL_FLAG_ACK      = 0b0010000000;
constexpr uint16_t EAPOL_FLAG_SECURE   = 0b1000000000;

void exec(const std::vector<std::string>& cmd, bool check = true);
std::string get_macaddress(const std::string& iface);
void set_macaddress(const std::string& iface, const std::string& mac);

int  get_channel(const std::string& iface);

int chan2freq(int channel);

std::string get_ssid(const Tins::Dot11Beacon& beacon);

Tins::Dot11ProbeResponse* beacon_to_probe_resp(const Tins::Dot11Beacon& beacon, int rogue_channel);

// EAPOL helpers
int  get_eapol_msg_num(const Tins::Dot11Data& pkt);
uint64_t get_eapol_replay_num(const Tins::Dot11Data& pkt);
