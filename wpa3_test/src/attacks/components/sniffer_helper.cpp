#include "attacks/components/sniffer_helper.h"
#include <string>
#include "net_parser/eap_defs.h"
#include "net_parser/radiotap_defs.h"

namespace wpa3_tester::components {

bool radiotap_bad_fcs(const frame_raw_t &p, const uint16_t rt_len) {
	if(p.size() < sizeof(ieee80211_radiotap_header)) return false;
	auto *hdr = const_cast<ieee80211_radiotap_header *>(reinterpret_cast<const ieee80211_radiotap_header *>(p.data()));
	ieee80211_radiotap_iterator iter{};
	if(ieee80211_radiotap_iterator_init(&iter, hdr, rt_len, nullptr) != 0) return false;
	while(ieee80211_radiotap_iterator_next(&iter) == 0) {
		if(iter.is_radiotap_ns && iter.this_arg_index == IEEE80211_RADIOTAP_FLAGS)
			return *iter.this_arg & IEEE80211_RADIOTAP_F_BADFCS;
	}
	return false;
}

std::string eap_description_raw(const frame_raw_t &raw) {
	using namespace eap;
	static constexpr uint8_t snap_eapol[] = { ETHERTYPE_EAPOL_HI, ETHERTYPE_EAPOL_LO };
	const auto snap = std::ranges::search(raw, snap_eapol).begin();
	if(snap == raw.end()) return {};
	const size_t off = (snap - raw.begin()) + 2; // skip ethertype, EAPOL starts here
	if(off + 4 > raw.size()) return {};
	const auto eapol_type = static_cast<EapolType>(raw[off + 1]);
	if(eapol_type != EAPOL_EAP) {
		const auto name = to_string(eapol_type);
		return name.empty() ? "EAPOL type=" + std::to_string(raw[off + 1]) : std::string(name);
	}
	if(off + 9 > raw.size()) return "EAP";
	const auto code = static_cast<EapCode>(raw[off + 4]);
	if(code == CODE_REQUEST || code == CODE_RESPONSE) {
		const auto type = static_cast<EapType>(raw[off + 8]);
		const auto name = to_string(type);
		const std::string type_str = name.empty() ? "type=" + std::to_string(raw[off + 8]) : std::string(name);
		return "EAP-" + std::string(to_string(code)) + "/" + type_str;
	}
	return "EAP-" + std::string(to_string(code));
}

}
