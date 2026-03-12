#pragma once
#include <libssh/libssh.h>
#include "config/Actor_config.h"

namespace wpa3_tester{
    class RunStatus;
    class Actor_config;

    class ExternalConn{
    protected:
        Actor_config* actor;
        ssh_session session = nullptr;

    public:
        explicit ExternalConn(Actor_config* actor);
        virtual ~ExternalConn();
        virtual bool connect();

        virtual std::string get_hostname();
        virtual std::string get_interfaces();
        virtual std::string get_wifi_status();

        std::string exec(const std::string &cmd) const;

    };

}
