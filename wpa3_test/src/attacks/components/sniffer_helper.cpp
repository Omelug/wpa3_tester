#include "attacks/components/sniffer_helper.h"

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
	if(present0 & 1u << 0) off += 8;        // skip TSFT (8 bytes) if present
	return off < rt_len && p[off] & 0x40u;  // bit 6 = BAD_FCS
}

}
