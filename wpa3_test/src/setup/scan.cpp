#include "config/RunStatus.h"
#include "logger/error_log.h"
#include "system/hw_capabilities.h"


namespace wpa3_tester{
    using namespace std;
    using nlohmann::json;

    // main id is iface
    ActorCMap RunStatus::scan_internal(){
        ActorCMap options_map;
        for (const auto& [iface_name, iface_type] : hw_capabilities::list_interfaces()) {
            if(iface_type != InterfaceType::Wifi) continue; //TODO add to selection?
            json actor_json;
            actor_json["selection"]["iface"] = iface_name;
            auto cfg = make_unique<Actor_config>(actor_json);
            hw_capabilities::get_nl80211_caps(iface_name, *cfg);
            options_map.emplace(iface_name, std::move(cfg));
        }
        return options_map;
    }

    // ------------- EXTERNAL

    ActorCMap RunStatus::scan_external(){
        ActorCMap options_map;
        for (const auto& [iface_name, iface_type] : hw_capabilities:list_external()) {
            json actor_json;
            actor_json["selection"]["mac"] = ;
            actor_json["selection"]["ssid"] = ;
            auto cfg = make_unique<Actor_config>(actor_json);
            // get more info from one BSS
            //hw_capabilities::get_nl80211_caps(iface_name, *cfg);
            options_map.emplace(iface_name, std::move(cfg));
        }
        return options_map;
    }

    ActorCMap create_simulation(){
        throw not_implemented_error("simulation hwsim not implemented");
    }

}

