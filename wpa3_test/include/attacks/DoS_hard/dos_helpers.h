#pragma once
#include <cstdint>
#include <vector>

namespace wpa3_tester::dos_helpers {
    struct SAEPair {
        uint16_t group_id;
        std::vector<uint8_t> token;
        std::vector<uint8_t> scalar;
        std::vector<uint8_t> element;
        bool success = false;
    };

    std::optional<SAEPair> parse_sae_commit(const uint8_t *packet, uint32_t len);
}
