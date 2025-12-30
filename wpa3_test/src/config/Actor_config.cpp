#include "config/Actor_config.h"

using namespace std;
using json = nlohmann::json;

Actor_config::Actor_config(const json& j) {
    if (j.contains("selection") && j["selection"].is_object()) {
        const auto& sel = j["selection"];

        for (auto & [key, val] : str_con) {
            if (sel.contains(key) && sel[key].is_string()) {
                val = sel[key].get<string>();
            }
        }

        if (sel.contains("condition") && sel["condition"].is_array()) {
            for (const auto& cond_name : sel["condition"]) {
                if (auto key = cond_name.get<string>();
                    bool_conditions.contains(key)) {
                    bool_conditions[key] = true;
                }
            }
        }
    }
}


bool Actor_config::matches(const Actor_config& offer) {
    for (auto const & [key, required_val] : str_con) {
        if (!required_val.has_value()) { continue; }
        if (auto it = offer.str_con.find(key); it == offer.str_con.end() || it->second != required_val) {
            return false;
        }
    }

    // Check boolean conditions
    for(auto const& [key, required_val] : bool_conditions) {
        if (!required_val.has_value()) {continue;}
        if (auto it = offer.bool_conditions.find(key); it == offer.bool_conditions.end() || it->second != required_val) {
            return false;
        }
    }
    return true;
}