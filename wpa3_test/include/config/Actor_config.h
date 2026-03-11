#pragma once
#include <map>
#include <optional>
#include <string>
#include <nlohmann/json.hpp>

namespace wpa3_tester{
    inline auto MONITOR_IFACE_PREFIX = std::string("mon_");
    class Actor_config {
    public:
        explicit Actor_config() = default;
        explicit Actor_config(const nlohmann::json& j);
        bool matches(const Actor_config &offer);
        Actor_config &operator+=(const Actor_config &other);

        std::map<std::string, std::optional<std::string>> str_con = {
            {"actor_name",     std::nullopt},
            {"source",         std::nullopt},
            {"iface",          std::nullopt},
            {"mac",            std::nullopt},
            {"essid",          std::nullopt},
            {"driver",         std::nullopt},
            {"netns",          std::nullopt},
            {"sniff_iface",    std::nullopt},
            {"whitebox_host",  std::nullopt},
            {"whitebox_ip",    std::nullopt},
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

        //  only internal
        int run(const std::vector<std::string> &argv) const;
        void cleanup() const;
        void create_sniff_iface(const std::string & sniff_iface);

        // change interface status
        void set_channel(int channel) const;
        void set_managed_mode() const;
        void set_monitor_mode() const;

        void setup_actor(const nlohmann::json& config);
    private:
        void setup_actor_internal(const nlohmann::json& config);
        //setup_actor_external();
        //setup_actor_simulation();
    };
}