#include "attacks/mc_mitm/wifi_util.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"
#include <chrono>
#include <tins/tins.h>

#include "attacks/mc_mitm/client_state.h"

namespace wpa3_tester {
using namespace std;
using namespace chrono;
using namespace Tins;


/*
void handle_rx_real_chan(const unique_ptr<PDU> &pdu, const vector<uint8_t> &raw) {
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

	//SOLVE_OR_CONTINUE(handle_probe_real(addr2, *dot11))
	//TODO if(handle_action_real(addr2, *pdu, raw, *dot11)) return;
	SOLVE_OR_CONTINUE(handle_eapol_real(addr1, addr2, *dot11))
	SOLVE_OR_CONTINUE(handle_auth_from_client_real(addr1, *dot11))
	#undef SOLVE_OR_CONTINUE

	if(dot11->addr1() == ap.get(SK::mac)){ // -> AP
		if(client_state.get_mac() == addr2) display_traffic(*dot11, "Real channel");
		// STA -> AP
		if(dot11->find_pdu<Dot11Deauthentication>() || dot11->find_pdu<Dot11Disassoc>())
			client_state.update_state(ClientState::Target_disconnected);
	} else if(addr2 == ap.get(SK::mac)){ // AP ->
		//TODO FIXME refactirion
		handle_from_ap_real(pdu, *dot11, addr1);
	}
}*/
}