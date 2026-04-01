#include "attacks/DoS_hard/dos_helpers.h"

#include <algorithm>
#include <optional>

using namespace std;

namespace wpa3_tester::dos_helpers {
    optional<SAEPair> parse_sae_commit(const uint8_t *packet, const uint32_t len) {
        if (len < 4) return nullopt;

        const uint16_t radiotap_len = *reinterpret_cast<const uint16_t *>(packet + 2);

        constexpr size_t dot11_header = 24;
        constexpr size_t auth_fixed   = 6;
        const size_t auth_offset = radiotap_len + dot11_header;
        const size_t sae_offset  = auth_offset + auth_fixed;

        if (len <= sae_offset) return nullopt;

        const uint16_t algo   = *reinterpret_cast<const uint16_t *>(packet + auth_offset);
        const uint16_t seq    = *reinterpret_cast<const uint16_t *>(packet + auth_offset + 2); // commit
        const uint16_t status = *reinterpret_cast<const uint16_t *>(packet + auth_offset + 4);

        if (algo != 3 || seq != 1) return nullopt;

        const uint8_t *sae_data = packet + sae_offset;
        const size_t   sae_size = len - sae_offset;

        SAEPair frame;
        frame.group_id = *reinterpret_cast<const uint16_t *>(sae_data);
        constexpr size_t ACM_status = 76;
        if (status == ACM_status) {
            // Token present — sits between group_id and scalar+element
            if (sae_size < 3) return nullopt; // at least group(2) + 1 token byte
            frame.token.assign(sae_data + 2, sae_data + sae_size);
        } else {
            // Normal commit — no token
            if (sae_size < (2 + 32 + 64)) return nullopt;
            frame.scalar.assign(sae_data + 2,  sae_data + 34);
            frame.element.assign(sae_data + 34, sae_data + 98);
        }

        frame.success = true;
        return frame;
    }

}
