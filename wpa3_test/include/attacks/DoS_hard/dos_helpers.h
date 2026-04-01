#pragma once
#include <cstdint>
#include <vector>

namespace wpa3_tester::dos_helpers {
    struct SAEPair {
        uint16_t status;
        mutable uint16_t group_id;
        std::vector<uint8_t> token;
        std::vector<uint8_t> scalar;
        std::vector<uint8_t> element;
        bool success = false;
    };

    std::optional<SAEPair> parse_sae_commit(const uint8_t *packet, uint32_t len);
    Tins::RadioTap make_sae_commit(const Tins::HWAddress<6> &ap_mac,
                                          const Tins::HWAddress<6> &sta_mac,
                                          SAEPair sae_params);
}
