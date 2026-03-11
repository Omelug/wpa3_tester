#include "config/Actor_config.h"
#include "logger/error_log.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester{
    using namespace std;

    void Actor_config::setup_actor(const nlohmann::json& config){
        if(str_con.at("source").value() == "internal") setup_actor_internal(config);
        throw not_implemented_error("external and internal not supported yet"); //TODO
    }

    void Actor_config::setup_actor_internal(const nlohmann::json& config){
        auto actor_json = config.at("actors").at(str_con["actor_name"].value());
        if (actor_json.contains("netns")) {
            const optional<string> netns_opt;
            str_con["netns"] = actor_json.at("netns").get<string>();
            hw_capabilities::create_ns(netns_opt.value());
        }
        this->cleanup();
        const bool monitor = bool_conditions.at("monitor").value_or(false);
        const bool injection = bool_conditions.at("injection").value_or(false);
        if ((monitor || injection) && str_con["sniff_iface"] == nullopt){set_monitor_mode();}
        if (bool_conditions.at("AP").value_or(false)){set_managed_mode();}
        if (actor_json.contains("channel")) {set_channel(actor_json.at("channel"));}
        if (actor_json.contains("sniff_iface")){
            str_con["sniff_iface"] = actor_json.at("sniff_iface").get<string>();
            create_sniff_iface(MONITOR_IFACE_PREFIX + str_con["sniff_iface"].value());
        }
    }
}
