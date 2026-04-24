#include "attacks/DoS_hard/dos_helpers.h"
#include <optional>

extern "C"{
#include "radiotap.h"
#include "radiotap_iter.h"
}

#include "logger/log.h"

using namespace std;
using namespace Tins;

namespace wpa3_tester::dos_helpers{
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

bool check_fcs_present(const uint8_t *packet, const uint32_t len){
    ieee80211_radiotap_iterator it;

    auto *header = (struct ieee80211_radiotap_header *)packet;

    if(ieee80211_radiotap_iterator_init(&it, header, static_cast<int>(len), nullptr) != 0){
        return false;
    }

    while(ieee80211_radiotap_iterator_next(&it) == 0){
        if(it.this_arg_index == IEEE80211_RADIOTAP_FLAGS){
            if(it.this_arg != nullptr){
                const uint8_t flags = *it.this_arg;
                return (flags & 0x10); // 0x10 = FCS at end
            }
        }
    }

    return false;
}

optional<SAEPair> parse_sae_commit(const uint8_t *frame_rt, const uint32_t len){
    // --- RadioTap ---
    if(len < 4) return nullopt;
    const uint16_t radiotap_len = frame_rt[2] | (frame_rt[3] << 8);

    const bool has_fcs = check_fcs_present(frame_rt, len);

    // --- Offsety ---
    constexpr size_t dot11_header = 24;
    constexpr size_t auth_fixed = 6; // Algo(2) + Seq(2) + Status(2)
    const size_t auth_offset = radiotap_len + dot11_header;
    const size_t sae_offset = auth_offset + auth_fixed;

    if(len < sae_offset + 2) return nullopt;

    /*fprintf(stderr, "DEBUG radiotap_len=%u\n", radiotap_len);
        fprintf(stderr, "DEBUG auth_offset={}\n", auth_offset);
        fprintf(stderr, "DEBUG bytes at auth_offset: %02x %02x %02x %02x %02x %02x\n",
                frame_rt[auth_offset],   frame_rt[auth_offset+1],
                frame_rt[auth_offset+2], frame_rt[auth_offset+3],
                frame_rt[auth_offset+4], frame_rt[auth_offset+5]);*/

    // --- Auth header ---
    const uint16_t algo = frame_rt[auth_offset] | (frame_rt[auth_offset + 1] << 8);
    const uint16_t seq = frame_rt[auth_offset + 2] | (frame_rt[auth_offset + 3] << 8);
    const uint16_t status = frame_rt[auth_offset + 4] | (frame_rt[auth_offset + 5] << 8);

    if(algo != 3 || seq != 1) return nullopt;

    // --- SAE data (za auth_fixed) ---
    const uint8_t *sae_data = frame_rt + sae_offset;
    size_t remaining = len - sae_offset;
    if(has_fcs && remaining >= 4) remaining -= 4;

    if(remaining < 2) return nullopt;

    // --- Group ID ---
    SAEPair frame;
    frame.status = status;
    frame.group_id = static_cast<uint16_t>(sae_data[0]) | (static_cast<uint16_t>(sae_data[1]) << 8);

    size_t scalar_len = 0;
    size_t element_len = 0;
    switch(frame.group_id){
        case 19: scalar_len = 32;
            element_len = 64;
            break; // NIST P-256
        case 20: scalar_len = 48;
            element_len = 96;
            break; // NIST P-384
        case 21: scalar_len = 66;
            element_len = 132;
            break; // NIST P-521
        default: return nullopt;
    }

    const size_t crypto_total = scalar_len + element_len;
    const uint8_t *ptr = sae_data + 2; // skip Group ID
    remaining -= 2;

    // --- Token + Scalar + Element depends on status code (wireshark packet-ieee80211.c) ---

    if(status == 76){
        // only anti-clogging token, no scalar/element
        if(remaining > 0) frame.token.assign(ptr, ptr + remaining);
        return frame;
    }

    if(status == 0 || status == 126){
        // Token if more data than scalar+element
        if(remaining > crypto_total){
            const size_t token_len = remaining - crypto_total;
            frame.token.assign(ptr, ptr + token_len);
            ptr += token_len;
            remaining -= token_len;
        }

        // Scalar + Element
        if(remaining < crypto_total) return nullopt;
        frame.scalar.assign(ptr, ptr + scalar_len);
        frame.element.assign(ptr + scalar_len, ptr + crypto_total);
        return frame;
    }

    // status 77 — group ID ok, but  scalar/element //FIXME
    return frame;
}

RadioTap make_sae_commit(const HWAddress<6> &ap_mac, const HWAddress<6> &sta_mac,
                         const SAEPair &sae_params
){
    //TODO check invalid  combinations of params chekc
    if(!sae_params.is_valid()){}

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