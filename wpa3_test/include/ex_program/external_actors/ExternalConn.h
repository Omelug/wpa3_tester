#pragma once
#include <libssh/libssh.h>
#include "config/ActorPtr.h"
#include "logger/error_log.h"

namespace wpa3_tester{
    class RunStatus;
    class Actor_config;
    class ExternalConn{
    protected:
        ssh_session session = nullptr;
    public:
        explicit ExternalConn();
        virtual ~ExternalConn();
        virtual bool connect(const RunStatus &rs, const ActorPtr &actor);

        virtual std::string get_hostname();
        virtual std::vector<std::string> get_radio_list();
        std::string get_mac_address(const std::string &iface) const;
        std::string get_driver(const std::string &radio) const;

        virtual std::string exec(const std::string &cmd, int * ret_err = nullptr) const;
        void create_sniff_iface(const std::string &iface, const std::string &sniff_iface) const;
        bool set_channel(const std::string &iface, int channel) const;
        virtual void set_monitor_mode(const std::string & iface) const;
        virtual void set_managed_mode(const std::string & iface) const;
        virtual void set_ip(const std::string &iface, const std::string &ip_addr) const;

        virtual void setup_ap(const RunStatus &rs, const ActorPtr &actor) = 0;
        virtual void setup_iface(const std::string &radio_name, const std::shared_ptr<Actor_config> &actor) = 0;
        virtual void check_req(const nlohmann::json &config, const std::string &actor_name) = 0;
        virtual void logger(RunStatus& rs, const std::string & actor_name) = 0;
        virtual void get_hw_capabilities(Actor_config& cfg, const std::string& radio) = 0;
    };
}
