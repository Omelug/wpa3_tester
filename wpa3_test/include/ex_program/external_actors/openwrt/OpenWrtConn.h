#pragma once
#include <string>

#include "config/RunStatus.h"
#include "ex_program/external_actors/ExternalConn.h"

namespace wpa3_tester {
    class OpenWrtConn : public ExternalConn {
        std::thread logger_thread;
        // --- device functions
        void check_req(const nlohmann::json &config, const std::string &actor_name) override;
        std::string wait_for_ifname(const std::string &section) const;

    public:
        void forward_internet(const std::string &remote_ip) const;
        void time_fix() const;

        void setup_iface(const std::string &radio_name, const std::shared_ptr<Actor_config> &actor, nlohmann::json config) override;

        explicit OpenWrtConn() = default;
        bool connect(const ActorPtr &actor) override;
        std::vector<std::string> get_radio_list() override;

        void set_monitor_mode(const std::string &iface) const override;
        void set_managed_mode(const std::string &iface) const override;
        void set_ip(const std::string &iface, const std::string &ip_addr) const override;
        std::string get_radio(const std::string &iface) const;
        std::string get_wifi_iface_section(const std::string &iface) const;
        void setup_ap(const RunStatus &rs, const ActorPtr &actor) override;
        void logger(RunStatus& rs, const std::string & actor_name) override;
        void get_hw_capabilities(Actor_config& cfg, const std::string& radio) override;
        static void parse_hw_capabilities(Actor_config& cfg, const std::string& output);
    };
}
