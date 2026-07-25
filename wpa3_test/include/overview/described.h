#pragma once
#include <optional>
#include <string>
#include <vector>

namespace wpa3_tester {

struct described_bool {
    struct pair_t {
        std::optional<bool> value;
        std::string description;
    };
    std::vector<pair_t> pairs;

    described_bool &operator+=(pair_t p) { pairs.push_back(std::move(p)); return *this; }

    [[nodiscard]] bool empty() const noexcept { return pairs.empty(); }
    [[nodiscard]] const pair_t &last() const { return pairs.back(); }
    [[nodiscard]] std::optional<bool> value() const {
        return pairs.empty() ? std::nullopt : pairs.back().value;
    }
};

struct described_str {
    struct pair_t {
        std::string value;
        std::string description;
    };
    std::vector<pair_t> pairs;

    described_str &operator+=(pair_t p) { pairs.push_back(std::move(p)); return *this; }

    [[nodiscard]] bool empty() const noexcept { return pairs.empty(); }
    [[nodiscard]] const pair_t &last() const { return pairs.back(); }
    [[nodiscard]] const std::string &value() const {
        static const std::string empty_s;
        return pairs.empty() ? empty_s : pairs.back().value;
    }
};

} // namespace wpa3_tester
