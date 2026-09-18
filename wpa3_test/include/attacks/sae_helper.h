#pragma once
#include <format>
#include <tins/tins.h>
#include <vector>

namespace wpa3_tester::sae_helper {
std::string bytes_to_hex(const std::vector<uint8_t> &bytes);
std::string bytes_to_hex_plain(const std::vector<uint8_t> &bytes);

struct SAEPair {
	uint16_t status = 0;
	mutable uint16_t group_id = 19;
	std::vector<uint8_t> token;
	std::vector<uint8_t> scalar;
	std::vector<uint8_t> element;

	bool is_valid() const {
		switch(status) {
		case 0:
		case 126: return !scalar.empty() && !element.empty();
		case 76: return !token.empty();
		case 77: return group_id != 0;
		default: return false;
		}
	}

	std::string to_str() const {
		return std::format(
			"SAEPair {{\n"
			"  status:   {}\n  group_id: {}\n  valid:    {}\n"
			"  scalar  ({} bytes): {}\n"
			"  element ({} bytes): {}\n"
			"  token   ({} bytes): {}\n}}",
			status, group_id, is_valid(),
			scalar.size(), bytes_to_hex(scalar),
			element.size(), bytes_to_hex(element),
			token.size(), bytes_to_hex(token));
	}
};

struct AuthFrame {
	Tins::HWAddress<6> addr1;
	uint16_t algorithm{};
	uint16_t seq{};
	uint16_t status{};
};

std::optional<AuthFrame> parse_auth_frame(const uint8_t *p, uint32_t caplen);
std::optional<SAEPair> parse_sae_commit(const std::vector<uint8_t> &frame_rt);
Tins::RadioTap make_sae_commit(
		const Tins::HWAddress<6> &ap_mac, const Tins::HWAddress<6> &sta_mac, const SAEPair &sae_params);
}