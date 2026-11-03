#include "attacks/components/sniffer_helper.h"
#include <algorithm>
#include <string>

namespace wpa3_tester::components {

bool radiotap_bad_fcs(const frame_raw_t &p, const uint16_t rt_len) {
	size_t off = 4;
	uint32_t present0 = 0;
	while(off + 4 <= static_cast<size_t>(rt_len)) {
		const uint32_t w = static_cast<uint32_t>(p[off]) | static_cast<uint32_t>(p[off + 1]) << 8 |
			static_cast<uint32_t>(p[off + 2]) << 16 | static_cast<uint32_t>(p[off + 3]) << 24;
		if(off == 4) present0 = w;
		off += 4;
		if(!(w & 1u << 31)) break;
	}
	if(!(present0 & 1u << 1)) return false; // Flags field not present
	if(present0 & 1u << 0) off += 8;		// skip TSFT (8 bytes) if present
	return off < rt_len && p[off] & 0x40u;	// bit 6 = BAD_FCS
}

//TODO simplify, test
std::string eap_description_raw(const frame_raw_t &raw) {
	static constexpr uint8_t snap_eapol[] = { 0x88, 0x8e };
	const auto snap = std::ranges::search(raw, snap_eapol).begin();
	if(snap == raw.end()) return {};
	const size_t off = (snap - raw.begin()) + 2; // skip ethertype, EAPOL starts here
	if(off + 4 > raw.size()) return {};
	const uint8_t eapol_type = raw[off + 1];
	if(eapol_type == 1) return "EAPOL-Start";
	if(eapol_type == 2) return "EAPOL-Logoff";
	if(eapol_type == 3) return "EAPOL-Key";
	if(eapol_type != 0) return "EAPOL type=" + std::to_string(eapol_type);
	if(off + 9 > raw.size()) return "EAP";
	const uint8_t code = raw[off + 4];
	if(code == 3) return "EAP-Success";
	if(code == 4) return "EAP-Failure";
	if(code == 1 || code == 2) {
		const std::string dir = code == 1 ? "Req" : "Resp";
		const uint8_t type = raw[off + 8];
		if(type == 1) return "EAP-" + dir + "/Identity";
		if(type == 21) return "EAP-" + dir + "/TTLS";
		if(type == 25) return "EAP-" + dir + "/PEAP";
		if(type == 52) return "EAP-" + dir + "/PWD";
		return "EAP-" + dir + " type=" + std::to_string(type);
	}
	return "EAP code=" + std::to_string(code);
}

}
