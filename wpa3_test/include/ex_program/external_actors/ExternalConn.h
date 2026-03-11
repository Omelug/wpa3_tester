#pragma once
#include <libssh/libssh.h>
#include "config/Actor_config.h"

namespace wpa3_tester{
    class ExternalConn{
        Actor_config* actor;
        ssh_session session = nullptr;
    public:
        explicit ExternalConn(Actor_config* actor);
        ~ExternalConn();
        bool connect();
        std::string exec(const std::string &cmd) const;
    };

}
