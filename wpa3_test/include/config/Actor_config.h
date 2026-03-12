#pragma once
#include <iostream>
#include <map>
#include <optional>
#include <string>
#include <type_traits>
#include <nlohmann/json.hpp>
#include <nlohmann/json_fwd.hpp>

#include "RunStatus.h"
#include "ex_program/external_actors/ExternalConn.h"

namespace wpa3_tester{
    inline auto MONITOR_IFACE_PREFIX = std::string("mon_");
    class ExternalConn;
    using ActorCMap = std::unordered_map<std::string, Actor_config*>;

    class Actor_config {
    public:
        explicit Actor_config() = default;
        explicit Actor_config(const nlohmann::json& j);
        bool matches(const Actor_config &offer);
        Actor_config &operator+=(const Actor_config &other);
        std::unique_ptr<ExternalConn> conn;

        std::map<std::string, std::optional<std::string>> str_con = {
            {"actor_name",     std::nullopt},
            {"source",         std::nullopt},
            {"iface",          std::nullopt},
            {"mac",            std::nullopt},
            {"essid",          std::nullopt},
            {"driver",         std::nullopt},
            {"netns",          std::nullopt},
            {"sniff_iface",    std::nullopt},
            // external whitebox only
            {"whitebox_host",  std::nullopt},
            {"whitebox_ip",    std::nullopt},
            {"ssh_user",       std::nullopt},
            {"ssh_port",       std::nullopt},
            {"ssh_password",   std::nullopt},
            {"external_OS",    std::nullopt},
        };

        std::map<std::string, std::optional<bool>> bool_conditions = {
            {"AP",          std::nullopt},
            {"injection",   std::nullopt},
            {"monitor",     std::nullopt},
            {"2_4GHz",      std::nullopt},
            {"5GHz",        std::nullopt},
            {"6GHz",        std::nullopt},
            {"WPA-PSK",     std::nullopt},
            {"WPA3-SAE",    std::nullopt},
            {"80211n",      std::nullopt},
            {"80211ac",     std::nullopt},
            {"80211ax",     std::nullopt},
            {"beacon_prot", std::nullopt}
        };

        std::string operator[](const std::string& key) const;
        bool get_bool(const std::string &key) const;
        std::string to_str() const;

        template<typename ActorMap>
        static void print_ActorCMap(const std::string& title, const ActorMap& actors);

        //  only internal
        int run(const std::vector<std::string> &argv) const;
        void cleanup() const;
        void create_sniff_iface(const std::string & sniff_iface);

        // change interface status
        void set_channel(int channel) const;
        void set_managed_mode() const;
        void set_monitor_mode() const;

        void setup_actor(const nlohmann::json& config, const Actor_config* real_actor);
    private:
        void setup_actor_internal(const nlohmann::json &config, const Actor_config *real_actor);
        void setup_actor_external_whitebox(const nlohmann::json & config, const Actor_config *real_actor);
        //setup_actor_simulation();
    };

    // Template implementation must be in header
    template<typename ActorMap>
    void Actor_config::print_ActorCMap(const std::string& title, const ActorMap& actors) {
        std::cout << title << ":" << std::endl;
        for (const auto& [key, actor_ptr] : actors) {
            const Actor_config* actor = [&]() -> const Actor_config* {
                if constexpr (std::is_same_v<typename ActorMap::mapped_type, Actor_config*>)
                    return actor_ptr;
                else
                    return actor_ptr.get();  // unique_ptr
            }();
            std::cout << "[" << key << "] ";
            if (actor->str_con.at("whitebox_host").has_value()) {
                std::cout << actor->str_con.at("whitebox_host").value();
            } else {
                std::cout << "Actor_" << key << " ";
            }
            std::cout << actor->to_str() << "\n";
        }
        std::cout << std::flush;
    }
}
