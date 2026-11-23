#pragma once
#include <cstddef>
#include <cstdint>
#include <format>
#include <map>

// IEEE 802.11-2024, SAE (Simultaneous Authentication of Equals) constants

namespace wpa3_tester::sae_defs {

// Sequence numbers -- IEEE 802.11-2024, Section 12.4.4
enum SaeSeq : uint16_t {
	SAE_COMMIT_SEQ  = 1,
	SAE_CONFIRM_SEQ = 2,
};

// SAE-related status codes - IEEE 802.11-2024, Table 9-50
// SAE-specific status codes - IEEE 802.11-2024, Table 9-50
// (STATUS_SUCCESS = 0 is in dot11_defs.h)
enum SaeStatus : uint16_t {
	STATUS_ANTI_CLOGGING            = 76,  // ANTI_CLOGGING_TOKEN_REQUIRED
	STATUS_UNSUPPORTED_GROUP        = 77,  // UNSUPPORTED_FINITE_CYCLIC_GROUP
	STATUS_REJECTED_WITH_SUGGESTION = 126, // rejected, peer still sends scalar+element
};
// Finite cyclic group IDs - IEEE 802.11-2024, Section 12.4.4.2
enum SaeGroup : uint16_t {
	P256         = 19, // NIST P-256
	P384         = 20, // NIST P-384
	P521         = 21, // NIST P-521
	MODP_1024    = 22, // RFC 5114 MODP 1024-bit (vulnerable to timing, Dragonblood Sec.6)
	MODP_2048    = 23, // RFC 5114 MODP 2048-bit
	MODP_2048_256= 24, // RFC 5114 MODP 2048-bit 256-bit subgroup
};
// Finite cyclic group parameters - IEEE 802.11-2024, Section 12.4.4.2
struct GroupParams {
	size_t scalar_len;
	size_t element_len; // uncompressed point = 2 * prime length
};

// prime field groups (ECC): scalar = prime length, element = 2 * prime length
// MODP groups (RFC 5114): scalar = element = prime length in bytes
inline const std::map<SaeGroup, GroupParams> group_params = {
	{P256,          { 32,  64}},
	{P384,          { 48,  96}},
	{P521,          { 66, 132}},
	{MODP_1024,     {128, 128}},
	{MODP_2048,     {256, 256}},
	{MODP_2048_256, {256, 256}},
};

}
template<>
struct std::formatter<wpa3_tester::sae_defs::SaeGroup> : std::formatter<uint16_t> {
	auto format(const wpa3_tester::sae_defs::SaeGroup g, std::format_context &ctx) const {
		return std::formatter<uint16_t>::format(g, ctx);
	}
};
