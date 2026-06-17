#pragma once
#include <chrono>
#include <optional>
#include <string_view>
#include <vector>
#include <tins/hw_address.h>
#include "attacks/components/sniffer_helper.h"
#include "attacks/mc_mitm/MonitorSocket.h"
#include "system/wifi_channel.h"

namespace wpa3_tester::reflection {

struct EapPwdFrame {
    uint8_t              eap_id{};
    uint8_t              opcode{};
    std::vector<uint8_t> pwd_data;
};

struct EAP_Att {
    MonitorSocket&                sock;
    const Channel&                channel;
    const Tins::HWAddress<6>&     att_mac;
    const Tins::HWAddress<6>&     ap_mac;
    std::string_view              ssid;
    std::string_view              identity;
    std::chrono::milliseconds     timeout;

    void decrease_timeout(const std::chrono::time_point<std::chrono::steady_clock> start_time) {
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start_time);
        timeout = elapsed >= timeout ? std::chrono::milliseconds{0} : timeout - elapsed;
    }
};

// ---------- parse helpers ----------
std::optional<EapPwdFrame> parse_eap_pwd(const std::vector<uint8_t>& eapol);
bool is_identity_request(const std::vector<uint8_t>& eapol, uint8_t& out_eap_id);
bool is_eap_success(const std::vector<uint8_t>& eapol);

// ---------- build helpers ----------
std::vector<uint8_t> build_identity_response(uint8_t eap_id, std::string_view identity);
std::vector<uint8_t> build_pwd_id_response(const EapPwdFrame& request, std::string_view peer_identity);
std::vector<uint8_t> reflect_commit(const EapPwdFrame& request);
std::vector<uint8_t> reflect_confirm(const EapPwdFrame& request);

// ---------  EAP-pwd connect ---------
// handle and send another phase packet
// return if continue
bool send_eap_normal_EAP(EAP_Att &eap_att);
bool send_eap_normal_EAP_pwd_ID(EAP_Att &eap_att);
// connected (only EAP, not fully connected)
bool eap_pwd_wait_for_success(EAP_Att &eap_att);

// ---------- 802.11 helpers ----------
bool do_auth(EAP_Att& eap_att);
bool do_assoc(EAP_Att& eap_att);
void send_eapol(const EAP_Att& eap_att, const std::vector<uint8_t>& eapol);

std::vector<uint8_t> extract_eapol(const uint8_t* p, uint32_t caplen,
                                    const Tins::HWAddress<6>& our_mac);

// Definition must be in the header: abbreviated function template, each lambda
// instantiation needs the definition visible in the calling TU.
std::optional<std::vector<uint8_t>> wait_eapol(EAP_Att& eap_att, auto pred){
	const auto start_time = std::chrono::steady_clock::now();
	std::optional<std::vector<uint8_t>> result = std::nullopt;
    (void)components::poll_sniffer<bool>(eap_att.sock.get_pcap_handle(), eap_att.timeout,
        [&](const uint8_t* p, const uint32_t caplen) -> std::optional<bool> {
            auto eapol = extract_eapol(p, caplen, eap_att.att_mac);
            if (eapol.empty()) return std::nullopt;
            if (is_eap_success(eapol)){
            	result = std::vector<uint8_t>{}; //hae to be empty vector
            	return true;
            }
            if (!pred(eapol)) return std::nullopt;
            result = std::move(eapol);
            return true;
        });
    eap_att.decrease_timeout(start_time);
    return result;
}

}