#pragma once
#include <libssh/libssh.h>
#include "config/ActorPtr.h"

namespace wpa3_tester{
    class RunStatus;
    class Actor_config;
    class ExternalConn{
    protected:
        ActorPtr actor;
        ssh_session session = nullptr;

    public:
        explicit ExternalConn(const ActorPtr &actor);
        virtual ~ExternalConn();
        virtual bool connect();

        virtual std::string get_hostname();
        virtual std::vector<std::string> get_interfaces();
        virtual std::string get_wifi_status();
        std::string get_mac_address(const std::string &iface) const;
        std::string get_driver(const std::string &iface) const;

        std::string exec(const std::string &cmd, int * ret_err = nullptr) const;
        void create_sniff_iface(const std::string &iface, const std::string &sniff_iface) const;
        bool set_channel(const std::string &iface, int channel) const;
        virtual void set_monitor_mode(const std::string & iface) const;
        virtual void set_managed_mode(const std::string & iface) const;
    };

}
