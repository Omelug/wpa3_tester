#pragma once
#include <cstddef>
#include <cstdint>
#include <map>

// IEEE 802.11-2020, SAE (Simultaneous Authentication of Equals) constants

namespace wpa3_tester::sae_defs {

// Sequence numbers -— IEEE 802.11-2020, Section 12.4.4
enum SaeSeq : uint16_t {
	SAE_COMMIT_SEQ  = 1,
	SAE_CONFIRM_SEQ = 2,
};

// SAE-related status codes - IEEE 802.11-2020, Table 9-50
// SAE-specific status codes - IEEE 802.11-2020, Table 9-50
// (STATUS_SUCCESS = 0 is in dot11_defs.h)
enum SaeStatus : uint16_t {
	STATUS_ANTI_CLOGGING            = 76,  // ANTI_CLOGGING_TOKEN_REQUIRED
	STATUS_UNSUPPORTED_GROUP        = 77,  // UNSUPPORTED_FINITE_CYCLIC_GROUP
	STATUS_REJECTED_WITH_SUGGESTION = 126, // rejected, peer still sends scalar+element
};

// Finite cyclic group parameters - IEEE 802.11-2020, Section 12.4.4.2
struct GroupParams {
	size_t scalar_len;
	size_t element_len; // uncompressed point = 2 * prime length
};

// prime field groups (ECC): scalar = prime length, element = 2 * prime length
inline const std::map<uint16_t, GroupParams> group_params = {
	{19, {32,  64}}, // NIST P-256
	{20, {48,  96}}, // NIST P-384
	{21, {66, 132}}, // NIST P-521
};

}
