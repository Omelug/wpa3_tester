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

// ---------------------------------------------------------------------------
// Interface helpers (wrapping iw / ifconfig shell commands)
// ---------------------------------------------------------------------------

void exec(const std::vector<std::string>& cmd, bool check = true);
//std::string exec_output(const std::vector<std::string>& cmd);

std::string get_macaddress(const std::string& iface);
void set_macaddress(const std::string& iface, const std::string& mac);

int  get_channel(const std::string& iface);
void set_channel(const std::string& iface, int channel);

int chan2freq(int channel);

std::string get_iface_type(const std::string& iface);
std::string get_device_driver(const std::string& iface);

void set_monitor_mode(const std::string& iface, bool up = true, int mtu = 1500);
//bool set_monitor_active(const std::string& iface);
void set_ap_mode(const std::string& iface);

// Returns the raw beacon bytes (head+tail) and starts the AP via iw
void start_ap(const std::string& iface, const int channel, Tins::Dot11Beacon* beacon = nullptr);
void stop_ap(const std::string& iface);

// ---------------------------------------------------------------------------
// 802.11 frame helpers
// ---------------------------------------------------------------------------


bool dot11_is_encrypted_data(const Tins::Dot11Data& pkt);
bool dot11_is_group(const Tins::Dot11& pkt);

// Returns the SSID from a beacon, or empty string
std::string get_ssid(const Tins::Dot11Beacon& beacon);

// Returns pointer to IE with given type, or nullptr
const Tins::Dot11::option* get_element(const Tins::Dot11& pkt, uint8_t id);

// Build a CSA IE
Tins::Dot11::option construct_csa(int channel, int count = 1);

// Clone beacon and append a CSA element
Tins::Dot11Beacon* append_csa(const Tins::Dot11Beacon& beacon, int channel, int count = 1);

// Convert a beacon to a probe response
Tins::Dot11ProbeResponse* beacon_to_probe_resp(const Tins::Dot11Beacon& beacon);

// Search for a network by SSID. Returns raw beacon bytes or empty on timeout.
std::vector<uint8_t> find_network(const std::string& iface,
                                  const std::string& ssid,
                                  int timeout_ms = 300);

// EAPOL helpers
int  get_eapol_msg_num(const Tins::Dot11Data& pkt);
uint64_t get_eapol_replay_num(const Tins::Dot11Data& pkt);
