#include "config/Actor_config.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester{
    using namespace std;

    void Actor_config::setup_actor(const nlohmann::json& config, const wpa3_tester::ActorPtr &real_actor){
        const bool internal = str_con.at("source").value() == "internal";
        const bool external_WB = str_con.at("source").value() == "external" &&
            (real_actor->str_con.at("whitebox_host").has_value() || real_actor->str_con.at("whitebox_ip").has_value());
        if(internal || external_WB){
            // (same if set in config)
            str_con["driver"] = real_actor->str_con.at("driver");
            str_con["mac"] = real_actor->str_con.at("mac");
            str_con["iface"] = real_actor->str_con.at("iface");
        }

        if(internal) setup_actor_internal(config, real_actor);
        if(external_WB){setup_actor_external_whitebox(config, real_actor);}
        if(internal || external_WB){
            auto actor_json = config.at("actors").at(str_con["actor_name"].value());
            const bool monitor = bool_conditions.at("monitor").value_or(false);
            const bool injection = bool_conditions.at("injection").value_or(false);
            if (bool_conditions.at("AP").value_or(false)){set_managed_mode();}
            if (actor_json.contains("channel")) {set_channel(actor_json.at("channel"));}
            if ((monitor || injection) && str_con["sniff_iface"] == nullopt){set_monitor_mode();}
            if (actor_json.contains("sniff_iface")){
                str_con["sniff_iface"] = actor_json.at("sniff_iface").get<string>();
                create_sniff_iface(MONITOR_IFACE_PREFIX + str_con["sniff_iface"].value());
            }

        }

    }

    void Actor_config::setup_actor_internal(const nlohmann::json& config, const ActorPtr &real_actor){
        auto actor_json = config.at("actors").at(str_con.at("actor_name").value());
        this->cleanup();
        if (actor_json.contains("netns")) {
            str_con["netns"] = actor_json.at("netns").get<string>();
            hw_capabilities::create_ns(str_con.at("netns").value());
        }
    }

    void Actor_config::setup_actor_external_whitebox(const nlohmann::json& config, const ActorPtr &real_actor){
        auto actor_json = config.at("actors").at(str_con["actor_name"].value());
        //this->cleanup();
    }


}
