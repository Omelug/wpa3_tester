#pragma once
#include <format>
#include <tins/tins.h>
#include <vector>

#include "config/RunStatus.h"
#include "net_parser/dot11_defs.h"
#include "net_parser/sae_defs.h"

namespace wpa3_tester::sae_helper {
std::string bytes_to_hex(const frame_raw_t &bytes);
std::string bytes_to_hex_plain(const frame_raw_t &bytes);

struct SAEPair {
	uint16_t status = 0;
	mutable sae_defs::SaeGroup group_id = sae_defs::SaeGroup::P256;
	std::vector<uint8_t> token;
	std::vector<uint8_t> scalar;
	std::vector<uint8_t> element;

	bool is_valid() const {
		switch(status) {
		case dot11::STATUS_SUCCESS:
		case sae_defs::STATUS_REJECTED_WITH_SUGGESTION: return !scalar.empty() && !element.empty();
		case sae_defs::STATUS_ANTI_CLOGGING:            return !token.empty();
		case sae_defs::STATUS_UNSUPPORTED_GROUP:        return group_id != 0;
		default: return false;
		}
	}

	std::string to_str() const {
		return std::format("SAEPair {{\n"
						   "  status:   {}\n  group_id: {}\n  valid:    {}\n"
						   "  scalar  ({} bytes): {}\n"
						   "  element ({} bytes): {}\n"
						   "  token   ({} bytes): {}\n}}",
			status,
			group_id,
			is_valid(),
			scalar.size(),
			bytes_to_hex(scalar),
			element.size(),
			bytes_to_hex(element),
			token.size(),
			bytes_to_hex(token));
	}
};

struct AuthFrame {
	Tins::HWAddress<6> addr1;
	uint16_t algorithm{};
	uint16_t seq{};
	uint16_t status{};
};

std::optional<AuthFrame> parse_auth_frame(const frame_raw_t &p);
std::optional<SAEPair> parse_sae_commit(const frame_raw_t &frame_rt);
Tins::RadioTap make_sae_commit(
	const Tins::HWAddress<6> &ap_mac, const Tins::HWAddress<6> &sta_mac, const SAEPair &sae_params);
// Garbage SAE Confirm (seqnum=2) - verifier will fail AP's check, but AP still processes it
Tins::RadioTap make_sae_confirm(const Tins::HWAddress<6> &ap_mac, const Tins::HWAddress<6> &sta_mac);
// SAE Commit using hardcoded MODP scalar+element
// groups 22/23/24, from RFC 5114
// ECC brainpool groups (27-30) would need OpenSSL to generate valid EC points
Tins::RadioTap make_modp_commit(
	const Tins::HWAddress<6> &ap_mac, const Tins::HWAddress<6> &sta_mac, sae_defs::SaeGroup group_id);
}