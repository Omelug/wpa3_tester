#include "config/Actor_config.h"

using namespace std;
using json = nlohmann::json;

Actor_config::Actor_config(const json& j) {
    if (j.contains("selection") && j["selection"].is_object()) {
        const auto& sel = j["selection"];

        if (sel.contains("mac"))   mac = sel["mac"].get<string>();
        if (sel.contains("essid")) essid = sel["essid"].get<string>();
        if (sel.contains("iface")) iface = sel["iface"].get<string>();

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
    if (mac.has_value() && mac != offer.mac) return false;
    if (iface.has_value() && iface != offer.iface) return false;
    if (essid.has_value() && essid != offer.essid) return false;

    for (auto const& [key, required_val] : bool_conditions) {
        if (!required_val.has_value()) {
            continue;
        }
        if (auto it = offer.bool_conditions.find(key);
            it == offer.bool_conditions.end() || it->second != required_val) {
            return false;
        }
    }
    return true;
}