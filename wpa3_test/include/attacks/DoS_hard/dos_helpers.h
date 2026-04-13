#pragma once
#include <cstdint>
#include <vector>

namespace wpa3_tester::dos_helpers {
    struct SAEPair {
        uint16_t status = 0;
        mutable uint16_t group_id = 19;
        std::vector<uint8_t> token;
        std::vector<uint8_t> scalar;
        std::vector<uint8_t> element;
        bool success = false;

        bool is_valid() const {
            if (!success) return false;

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
            auto bytes_to_hex = [](const std::vector<uint8_t> &bytes) -> std::string {
                if (bytes.empty()) return "(empty)";
                std::string result;
                for (size_t i = 0; i < bytes.size(); ++i) {
                    char buf[3];
                    snprintf(buf, sizeof(buf), "%02x", bytes[i]);
                    result += buf;
                    if (i < bytes.size() - 1) result += ":";
                }
                return result;
            };

            return "SAEPair {\n"
                   "  status:   " + std::to_string(status)           + "\n"
                   "  group_id: " + std::to_string(group_id)         + "\n"
                   "  success:  " + (success ? "true" : "false")     + "\n"
                   "  valid:    " + (is_valid() ? "true" : "false")  + "\n"
                   "  scalar  (" + std::to_string(scalar.size())  + " bytes): " + bytes_to_hex(scalar)  + "\n"
                   "  element (" + std::to_string(element.size()) + " bytes): " + bytes_to_hex(element) + "\n"
                   "  token   (" + std::to_string(token.size())   + " bytes): " + bytes_to_hex(token)   + "\n"
                   "}";
        }
    };

    std::optional<SAEPair> parse_sae_commit(const uint8_t *packet, uint32_t len);
    Tins::RadioTap make_sae_commit(const Tins::HWAddress<6> &ap_mac,
                                          const Tins::HWAddress<6> &sta_mac,
                                          const SAEPair &sae_params);
}
