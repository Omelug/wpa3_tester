#pragma once
#include <memory>
#include <nlohmann/json.hpp>

#include "config/Actor_Config/actor_keys.h"

namespace wpa3_tester{

class Actor_config;

struct HwInfo{
    friend class Actor_config;

    // returns true if the key represents persistent hardware capability
    // (suitable for caching and hw-capability filtering)
    static constexpr bool is_hw_info(const BK k){
        switch(k){
            case BK::AP: case BK::STA: case BK::monitor:
            case BK::GHz2_4: case BK::GHz5: case BK::GHz6:
            case BK::w80211n: case BK::w80211ac: case BK::w80211ax:
            case BK::beacon_prot:
            case BK::CSA:
            case BK::OCV:
            case BK::MFP:
                return true;
            default: return false;
        }
    }

    static constexpr bool is_hw_info(const SK k){
        return k == SK::permanent_mac || k == SK::driver_name || k == SK::driver_hash || k == SK::module_hash;
    }

private:
	std::shared_ptr<Actor_config> actor{};
	nlohmann::json to_json() const;
    void from_json(const nlohmann::json &j);
};

}
