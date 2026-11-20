#include "attacks/sae_helper.h"

#include "attacks/DoS_hard/dos_helpers.h"
#include "attacks/mc_mitm/MonitorSocket.h"
#include "logger/error_log.h"
#include "net_parser/dot11_defs.h"

using namespace std;
using namespace Tins;

namespace wpa3_tester::sae_helper {
string bytes_to_hex(const vector<uint8_t> &bytes) {
	if(bytes.empty()) return "(empty)";
	string result;
	result.reserve(bytes.size() * 3);
	bool first = true;
	for(const uint8_t b: bytes) {
		if(!first) result += ':';
		char buf[3];
		snprintf(buf, sizeof(buf), "%02x", b);
		result += buf;
		first = false;
	}
	return result;
}

string bytes_to_hex_plain(const vector<uint8_t> &bytes) {
	string result;
	result.reserve(bytes.size() * 2);
	for(const uint8_t b: bytes) {
		char buf[3];
		snprintf(buf, sizeof(buf), "%02x", b);
		result += buf;
	}
	return result;
}

optional<AuthFrame> parse_auth_frame(const frame_raw_t &p) {
	const uint16_t rt_len = radiotap::get_rt_len(p);
	if(!rt_len) return nullopt;
	if(p.size() < rt_len + dot11::MGMT_HDR_SIZE + dot11::AUTH_FIXED_SIZE) return nullopt;
	if(p[rt_len] != (dot11::MGMT_AUTH << dot11::FC_SUBTYPE_SHIFT)) return nullopt;
	const size_t auth_off = rt_len + dot11::MGMT_HDR_SIZE;
	return AuthFrame{
		.addr1 = HWAddress<6>(p.data() + rt_len + dot11::ADDR1_OFFSET),
		.algorithm = static_cast<uint16_t>(p[auth_off] | (p[auth_off + 1] << 8)),
		.seq = static_cast<uint16_t>(p[auth_off + 2] | (p[auth_off + 3] << 8)),
		.status = static_cast<uint16_t>(p[auth_off + 4] | (p[auth_off + 5] << 8)),
	};
}

optional<SAEPair> parse_sae_commit(const frame_raw_t &frame_rt) {
	const uint16_t radiotap_len = radiotap::get_rt_len(frame_rt);
	if(!radiotap_len) return nullopt;
	const bool has_fcs = dos_helpers::check_fcs_present(frame_rt);

	const size_t sae_offset = radiotap_len + dot11::MGMT_HDR_SIZE + dot11::AUTH_FIXED_SIZE;

	if(frame_rt.size() < sae_offset + 2) return nullopt;

	const size_t auth_offset = radiotap_len + dot11::MGMT_HDR_SIZE;
	const uint16_t algo = frame_rt[auth_offset] | (frame_rt[auth_offset + 1] << 8);
	const uint16_t seq = frame_rt[auth_offset + 2] | (frame_rt[auth_offset + 3] << 8);
	const uint16_t status = frame_rt[auth_offset + 4] | (frame_rt[auth_offset + 5] << 8);

	if(algo != dot11::AUTH_ALG_SAE || seq != sae_defs::SAE_COMMIT_SEQ) return nullopt;

	// Use span to avoid copying sae data
	const auto sae_data = span(frame_rt).subspan(sae_offset);
	size_t remaining = sae_data.size();
	if(has_fcs && remaining >= 4) remaining -= 4;

	if(remaining < 2) return nullopt;

	SAEPair frame;
	frame.status = status;
	frame.group_id = sae_data[0] | (static_cast<uint16_t>(sae_data[1]) << 8);

	const auto git = sae_defs::group_params.find(frame.group_id);
	if(git == sae_defs::group_params.end()) return nullopt;
	const size_t scalar_len  = git->second.scalar_len;
	const size_t element_len = git->second.element_len;

	const size_t crypto_total = scalar_len + element_len;
	auto ptr = sae_data.subspan(2); // skip Group ID
	remaining -= 2;
	// --- Token + Scalar + Element depends on status code (wireshark packet-ieee80211.c) ---
	if(status == sae_defs::STATUS_ANTI_CLOGGING) {
		// only anti-clogging token, no scalar/element
		if(remaining > 0) frame.token.assign(ptr.data(), ptr.data() + remaining);
		return frame;
	}

	if(status == dot11::STATUS_SUCCESS || status == sae_defs::STATUS_REJECTED_WITH_SUGGESTION) {
		// token if more data than scalar+element
		if(remaining > crypto_total) {
			const size_t token_len = remaining - crypto_total;
			frame.token.assign(ptr.data(), ptr.data() + token_len);
			ptr = ptr.subspan(token_len);
			remaining -= token_len;
		}
		// scalar + Element
		if(remaining < crypto_total) return nullopt;
		frame.scalar.assign(ptr.data(), ptr.data() + scalar_len);
		frame.element.assign(ptr.data() + scalar_len, ptr.data() + crypto_total);
		return frame;
	}

	return frame;
}

RadioTap make_sae_commit(const HWAddress<6> &ap_mac, const HWAddress<6> &sta_mac, const SAEPair &sae_params) {
	if(!sae_params.is_valid()) throw run_err("invalid combinations of sae params");

	Dot11Authentication auth(ap_mac, sta_mac);
	auth.addr3(ap_mac);
	auth.auth_algorithm(dot11::AUTH_ALG_SAE);
	auth.auth_seq_number(sae_defs::SAE_COMMIT_SEQ);
	auth.status_code(sae_params.status);

	// group 19 (P-256) | optional ACM token | dummy scalar | dummy element
	vector<uint8_t> payload;
	payload.reserve(2 + sae_params.token.size() + sae_params.scalar.size() + sae_params.element.size());
	payload.insert(payload.end(), {static_cast<uint8_t>(sae_params.group_id),
	                               static_cast<uint8_t>(sae_params.group_id >> 8)});
	payload.insert(payload.end(), sae_params.token.begin(), sae_params.token.end());
	payload.insert(payload.end(), sae_params.scalar.begin(), sae_params.scalar.end());
	payload.insert(payload.end(), sae_params.element.begin(), sae_params.element.end());

	auth.inner_pdu(RawPDU(payload));
	RadioTap rt{};
	rt.tx_flags(radiotap::TX_NOACK | radiotap::TX_ORDER);
	rt.inner_pdu(auth);
	return rt;
}

RadioTap make_sae_confirm(const HWAddress<6> &ap_mac, const HWAddress<6> &sta_mac) {
	Dot11Authentication auth(ap_mac, sta_mac);
	auth.addr3(ap_mac);
	auth.auth_algorithm(dot11::AUTH_ALG_SAE);
	auth.auth_seq_number(sae_defs::SAE_CONFIRM_SEQ);
	auth.status_code(dot11::STATUS_SUCCESS);
	// SC (2 bytes) + verifier (32 bytes zeros - garbage, AP will reject but still process)
	const size_t conf_size = sizeof(sae_defs::SaeSeq) + sae_defs::group_params.at(19).scalar_len; // P-256
	auth.inner_pdu(RawPDU(vector<uint8_t>(conf_size, 0)));
	RadioTap rt{};
	rt.tx_flags(radiotap::TX_NOACK | radiotap::TX_ORDER);
	rt.inner_pdu(auth);
	return rt;
}
}