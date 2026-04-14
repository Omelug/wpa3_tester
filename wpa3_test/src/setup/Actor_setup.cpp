#include "attacks/mc_mitm/wifi_util.h"
#include "config/Actor_config.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester{
    using namespace std;

    void Actor_config::set_mac(const string &mac_address){
        string mac_lower = mac_address;
        ranges::transform(mac_lower, mac_lower.begin(), [](const unsigned char c){ return tolower(c); });
        str_con["mac"] = mac_lower;
    }

    void Actor_config::setup_actor(const nlohmann::json& config, const ActorPtr &real_actor){
        const bool internal = str_con.at("source").value() == "internal";
        const bool external_WB = is_external_WB();
        conn = real_actor->conn;
        if(internal || external_WB){
            // (same if set in config)
            str_con["driver"] = real_actor->str_con.at("driver");
        }
        if(internal){
            if(!str_con["mac"].has_value()){
                set_mac(real_actor["mac"]);
            }else{
                setup_mac_addr(real_actor["mac"]);
            }
            str_con["iface"] = real_actor->str_con.at("iface");
            str_con["radio"] = real_actor->str_con.at("radio");
        }
        if(external_WB){
            str_con["whitebox_host"] = real_actor->str_con.at("whitebox_host");
            str_con["whitebox_ip"] = real_actor->str_con.at("whitebox_ip");
            str_con["ssh_user"] = real_actor->str_con.at("ssh_user");
            str_con["ssh_port"] = real_actor->str_con.at("ssh_port");
            str_con["ssh_password"] = real_actor->str_con.at("ssh_password");
            str_con["external_OS"] = real_actor->str_con.at("external_OS");
            const auto radio = real_actor->str_con["radio"].value();
            conn->setup_iface(radio, shared_from_this(), config);
        }


        if(internal) setup_actor_internal(config);
        if(external_WB){ setup_actor_external_whitebox(config, real_actor); }
        if(internal || external_WB){
            auto actor_json = config.at("actors").at(str_con["actor_name"].value());
            const bool monitor = bool_conditions.at("monitor").value_or(false);
            string monitor_flags;
            if (bool_conditions.at("active_monitor")) monitor_flags += " active";
            if (bool_conditions.at("control_monitor")) monitor_flags += " control";
            const bool injection = bool_conditions.at("injection").value_or(false);

            int channel = -1;
            if (const auto d = str_con["channel"]) channel = stoi(d.value());
            else if (const auto c = real_actor->str_con["channel"]) channel = stoi(c.value());
            if (channel != -1){
                 set_channel(channel, str_con["ht_mode"].value_or(""));
            }

            if ((monitor || injection) && str_con["sniff_iface"] == nullopt){set_monitor_mode(monitor_flags);}
            if (actor_json.contains("sniff_iface")){
                str_con["sniff_iface"] = MONITOR_IFACE_PREFIX + actor_json.at("sniff_iface").get<string>();
                create_sniff_iface(); //TODO add monitor flags ?
            }
            str_con["ssid"] = real_actor->str_con.at("ssid");
        }

        if(internal){
            //FIXMe shouod be avaible for external_WB
            if (bool_conditions.at("AP").value_or(false)){
                //set_managed_mode();
                set_ap_mode();
            }
            if (bool_conditions.at("managed").value_or(false)){set_managed_mode();}
            up_iface();
            up_sniff_iface();
        }

    }

    void Actor_config::setup_actor_internal(const nlohmann::json &config){
        const auto actor_name = str_con.at("actor_name").value();
        auto actor_json = config.at("actors").at(actor_name);
        if (actor_json.contains("netns")) {
            str_con["netns"] = actor_json.at("netns").get<string>();
            hw_capabilities::create_ns(str_con.at("netns").value());
        }
        this->cleanup();
    }

    void Actor_config::setup_actor_external_whitebox(const nlohmann::json& config, const ActorPtr &real_actor){
        auto actor_json = config.at("actors").at(str_con["actor_name"].value());
        //this->cleanup();
        real_actor->conn->check_req(config, str_con["actor_name"].value());
    }


}
