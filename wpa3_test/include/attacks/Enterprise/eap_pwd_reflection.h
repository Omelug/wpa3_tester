#pragma once
#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <tins/hw_address.h>
#include "attacks/mc_mitm/MonitorSocket.h"
#include "system/wifi_channel.h"

namespace wpa3_tester::reflection {

// Parsed EAP-PWD frame
struct EapPwdFrame {
    uint8_t              eap_id{};
    uint8_t              opcode{};
    std::vector<uint8_t> pwd_data; // payload after the PWD-Exch flags byte
};

// ---------- parse helpers ----------

// Extract EapPwdFrame from raw EAPOL bytes (with SNAP prefix stripped).
// Returns nullopt when the frame is not a valid EAP-PWD Request.
std::optional<EapPwdFrame> parse_eap_pwd(const std::vector<uint8_t>& eapol);

// True if EAPOL bytes contain EAP-Identity Request; writes the EAP identifier.
bool is_identity_request(const std::vector<uint8_t>& eapol, uint8_t& out_eap_id);

// True if EAPOL bytes contain EAP-Success.
bool is_eap_success(const std::vector<uint8_t>& eapol);

// ---------- build helpers ----------

// EAP-Response/Identity
std::vector<uint8_t> build_identity_response(uint8_t eap_id, std::string_view identity);

// EAP-Response/PWD-ID  – echo Group/RF/PRF/Token/Prep from request, append peer identity
std::vector<uint8_t> build_pwd_id_response(const EapPwdFrame& request, std::string_view peer_identity);

// EAP-Response/PWD-Commit – reflect server scalar+element verbatim
std::vector<uint8_t> reflect_commit(const EapPwdFrame& request);

// EAP-Response/PWD-Confirm – reflect server confirm value verbatim
std::vector<uint8_t> reflect_confirm(const EapPwdFrame& request);

// ---------- 802.11 helpers ----------

// Inject 802.11 Open-System Authentication Request and wait for the Response.
bool do_auth(MonitorSocket& sock, const Channel& ch,
             const Tins::HWAddress<6>& our_mac,
             const Tins::HWAddress<6>& ap_mac,
             std::chrono::milliseconds timeout);

// Inject 802.11 Association Request (with RSN IE for WPA2-EAP) and wait for Response.
bool do_assoc(MonitorSocket& sock, const Channel& ch,
              const Tins::HWAddress<6>& our_mac,
              const Tins::HWAddress<6>& ap_mac,
              std::string_view ssid,
              std::chrono::milliseconds timeout);

// Wrap EAPOL bytes in 802.11 Data/LLC/SNAP and send via MonitorSocket.
void send_eapol(MonitorSocket& sock, const Channel& ch,
                const Tins::HWAddress<6>& our_mac,
                const Tins::HWAddress<6>& ap_mac,
                const std::vector<uint8_t>& eapol);

// Extract raw EAPOL bytes from a raw radiotap+802.11 frame (strips LLC+SNAP).
// Returns empty vector when the frame is not an EAPOL Data frame addressed to our_mac.
std::vector<uint8_t> extract_eapol(const uint8_t* p, uint32_t caplen,
                                    const Tins::HWAddress<6>& our_mac);

// ---------- top-level ----------

// Full reflection exchange:  Auth → Assoc → EAP-PWD loop.
// Returns true when AP sends EAP-Success (server is vulnerable).
bool run_reflection_exchange(MonitorSocket& sock,
                              const Channel& channel,
                              const Tins::HWAddress<6>& our_mac,
                              const Tins::HWAddress<6>& ap_mac,
                              std::string_view ssid,
                              std::string_view identity,
                              std::chrono::seconds timeout);

} // namespace wpa3_tester::reflection