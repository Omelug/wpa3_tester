#include "attacks/components/sniffer_helper.h"
#include <algorithm>
#include <string>
#include "net_parser/eap_defs.h"

namespace wpa3_tester::components {

bool radiotap_bad_fcs(const frame_raw_t &p, const uint16_t rt_len) {
	size_t off = 4;
	uint32_t present0 = 0;
	const size_t cap = std::min(static_cast<size_t>(rt_len), p.size());
	while(off + 4 <= cap) {
		const uint32_t w = static_cast<uint32_t>(p[off]) | static_cast<uint32_t>(p[off + 1]) << 8 |
			static_cast<uint32_t>(p[off + 2]) << 16 | static_cast<uint32_t>(p[off + 3]) << 24;
		if(off == 4) present0 = w;
		off += 4;
		if(!(w & 1u << 31)) break;
	}
	if(!(present0 & 1u << 1)) return false; // Flags field not present
	if(present0 & 1u << 0) off += 8;		// skip TSFT (8 bytes) if present
	return off < cap && p[off] & 0x40u;	// bit 6 = BAD_FCS
}

std::string eap_description_raw(const frame_raw_t &raw) {
	using namespace eap;
	static constexpr uint8_t snap_eapol[] = { eap::ETHERTYPE_EAPOL_HI, eap::ETHERTYPE_EAPOL_LO };
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
	if(code == CODE_SUCCESS || code == CODE_FAILURE)
		return "EAP-" + std::string(to_string(code));
	if(code == CODE_REQUEST || code == CODE_RESPONSE) {
		const std::string dir = code == CODE_REQUEST ? "Req" : "Resp";
		const auto type = static_cast<EapType>(raw[off + 8]);
		const auto name = to_string(type);
		const std::string type_str = name.empty() ? "type=" + std::to_string(raw[off + 8]) : std::string(name);
		return "EAP-" + dir + "/" + type_str;
	}
	return "EAP code=" + std::to_string(raw[off + 4]);
}

}
