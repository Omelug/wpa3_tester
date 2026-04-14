#pragma once
#include <map>
#include <optional>
#include <string>
#include <nlohmann/json.hpp>
#include <nlohmann/json_fwd.hpp>
#include "ActorPtr.h"

namespace wpa3_tester{
    inline auto MONITOR_IFACE_PREFIX = std::string("mon_");
    class RunStatus;
    class ExternalConn;
    class Actor_config : public std::enable_shared_from_this<Actor_config>{
    public:
        explicit Actor_config() = default;
        Actor_config(const Actor_config& other);
        explicit Actor_config(const nlohmann::json& j);
        ~Actor_config();
        bool matches(const Actor_config &offer);
        Actor_config &operator+=(const Actor_config &other);
        std::shared_ptr<ExternalConn> conn;

        std::map<std::string, std::optional<std::string>> str_con = {
            {"actor_name",     std::nullopt},
            {"source",         std::nullopt},
            {"iface",          std::nullopt},
            {"mac",            std::nullopt},
            {"ssid",           std::nullopt},
            {"channel",        std::nullopt},
            {"signal",        std::nullopt},
            {"ht_mode",        std::nullopt},
            {"driver",         std::nullopt},
            {"netns",          std::nullopt},
            {"sniff_iface",    std::nullopt},
            // external whitebox only
            {"radio",          std::nullopt}, // same like phy for this project
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
            {"control_monitor",  std::nullopt},
            {"active_monitor",  std::nullopt},
            {"managed",     std::nullopt},
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
        static void print_ActorCMap(const std::string &title, const std::vector<ActorPtr> &actors);
        static void print_ActorCMap(const std::string& title, ActorCMap actors);
        bool is_WB() const;
        bool is_external_WB() const;

        //  only internal
        int run(const std::vector<std::string> &argv) const;
        void cleanup() const;
        void create_sniff_iface() const;

        // change interface status
        void set_channel(int channel, const std::string &ht_mode = "") const;
        void set_ap_mode() const;
        void down_iface() const;
        void up_iface() const;
        void up_sniff_iface() const;
        void set_managed_mode() const;
        void setup_mac_addr(const std::string &mac) const;
        void set_monitor_mode(const std::string &monitor_flags = "") const;
        void set_mac(const std::string &mac_address);
        void setup_actor(const nlohmann::json& config, const ActorPtr &real_actor);

    private:
        void setup_actor_internal(const nlohmann::json &config);
        void setup_actor_external_whitebox(const nlohmann::json & config, const ActorPtr &real_actor);
        //setup_actor_simulation();
    };

}
