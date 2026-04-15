#pragma once
#include <cstdint>
#include <vector>

namespace wpa3_tester::dos_helpers {

    std::string bytes_to_hex(const std::vector<uint8_t> &bytes);

    struct SAEPair {
        uint16_t status = 0;
        mutable uint16_t group_id = 19;
        std::vector<uint8_t> token;
        std::vector<uint8_t> scalar;
        std::vector<uint8_t> element;

        bool is_valid() const {

            switch (status) {
                case 0:
                case 126:
                    return !scalar.empty() && !element.empty();
                case 76:
                    return !token.empty();
                case 77:
                    return group_id != 0;
                default:
                    return false;
            }
        }

        std::string to_str() const {
            return "SAEPair {\n"
                   "  status:   " + std::to_string(status)           + "\n"
                   "  group_id: " + std::to_string(group_id)         + "\n"
                   "  valid:    " + (is_valid() ? "true" : "false")  + "\n"
                   "  scalar  (" + std::to_string(scalar.size())  + " bytes): " + bytes_to_hex(scalar)  + "\n"
                   "  element (" + std::to_string(element.size()) + " bytes): " + bytes_to_hex(element) + "\n"
                   "  token   (" + std::to_string(token.size())   + " bytes): " + bytes_to_hex(token)   + "\n"
                   "}";
        }
    };

    bool check_fcs_present(const uint8_t* packet, uint32_t len);
    std::optional<SAEPair> parse_sae_commit(const uint8_t *frame_rt, uint32_t len);
    Tins::RadioTap make_sae_commit(const Tins::HWAddress<6> &ap_mac,
                                          const Tins::HWAddress<6> &sta_mac,
                                          const SAEPair &sae_params);
}
