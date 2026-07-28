#pragma once
#include <optional>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

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

inline void to_json(nlohmann::json &j, const described_bool::pair_t &p){
	j = {{"value",       p.value.has_value() ? nlohmann::json(*p.value) : nlohmann::json(nullptr)},
	     {"description", p.description}};
}
inline void from_json(const nlohmann::json &j, described_bool::pair_t &p){
	j.at("description").get_to(p.description);
	const auto &v = j.at("value");
	p.value = v.is_null() ? std::nullopt : std::optional<bool>(v.get<bool>());
}
inline void to_json(nlohmann::json &j, const described_bool &d){ j = d.pairs; }
inline void from_json(const nlohmann::json &j, described_bool &d){ d.pairs = j.get<std::vector<described_bool::pair_t>>(); }

inline void to_json(nlohmann::json &j, const described_str::pair_t &p){
	j = {{"value", p.value}, {"description", p.description}};
}
inline void from_json(const nlohmann::json &j, described_str::pair_t &p){
	j.at("value").get_to(p.value);
	j.at("description").get_to(p.description);
}
inline void to_json(nlohmann::json &j, const described_str &d){ j = d.pairs; }
inline void from_json(const nlohmann::json &j, described_str &d){ d.pairs = j.get<std::vector<described_str::pair_t>>(); }

} // namespace wpa3_tester
