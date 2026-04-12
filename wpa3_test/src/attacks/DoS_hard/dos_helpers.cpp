#include "attacks/DoS_hard/dos_helpers.h"
#include <optional>

#include "logger/log.h"

using namespace std;
using namespace Tins;
namespace wpa3_tester::dos_helpers {

    optional<SAEPair> parse_sae_commit(const uint8_t *packet, uint32_t len) {
        if (len < 4) return nullopt;
        uint16_t rt_len = packet[2] | (packet[3] << 8);
        if (len <= rt_len + 24) return std::nullopt;

        bool has_fcs = (packet[14] & 0x10); // Bit 4

        const uint16_t radiotap_len = packet[2] | (packet[3] << 8);
        constexpr size_t dot11_header = 24;
        constexpr size_t auth_fixed   = 6; // Algo(2) + Seq(2) + Status(2)
        const size_t auth_offset = radiotap_len + dot11_header;
        const size_t sae_offset  = auth_offset + auth_fixed;

        if (len < sae_offset + 2) return nullopt;

        const uint16_t algo   = *reinterpret_cast<const uint16_t *>(packet + auth_offset);
        const uint16_t seq    = *reinterpret_cast<const uint16_t *>(packet + auth_offset + 2);
        const uint16_t status = *reinterpret_cast<const uint16_t *>(packet + auth_offset + 4);

        // SAE Commit musí mít Algo 3 a Sequence 1
        if (algo != 3 || seq != 1) return nullopt;

        const uint8_t *sae_data = packet + sae_offset;
        const size_t   sae_size = len - sae_offset;

        SAEPair frame;
        frame.status = status;
        frame.group_id = *reinterpret_cast<const uint16_t *>(sae_data);

        // length by Group ID
        size_t scalar_len = 0;
        size_t element_len = 0;

        switch (frame.group_id) {
            case 19: // NIST P-256
                scalar_len = 32;
                element_len = 64;
                break;
            case 20: // NIST P-384
                scalar_len = 48;
                element_len = 96;
                break;
            case 21: // NIST P-521
                scalar_len = 66;
                element_len = 132;
                break;
            default:
                throw std::runtime_error("Unknown group ID");
        }

        const size_t crypto_total = scalar_len + element_len;
        const size_t min_required = 2 + crypto_total;
        if (sae_size < min_required) return nullopt;
        if (sae_size < (2 + crypto_total)) return nullopt;

        size_t token_len = sae_size - 2 - crypto_total;
        if (has_fcs) {token_len -= 4; }
        if (token_len > 0){
            frame.token.assign(sae_data + 2, sae_data + 2 +token_len);
        }

        const uint8_t *crypto_ptr = sae_data + 2 + token_len;

        frame.scalar.assign(crypto_ptr, crypto_ptr + scalar_len);
        frame.element.assign(crypto_ptr + scalar_len, crypto_ptr + crypto_total);

        frame.success = true;
        return frame;
    }

    RadioTap make_sae_commit(const HWAddress<6> &ap_mac,const HWAddress<6> &sta_mac,
        SAEPair sae_params) {

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
