#pragma once
#include <libssh/libssh.h>
#include <string>

namespace wpa3_tester {
    class OpenWrtConn {
        ssh_session session = nullptr;

    public:
        explicit OpenWrtConn(const std::string& host, const std::string& user = "root", int port = 22);
        ~OpenWrtConn();

        std::string exec(const std::string& cmd);
        std::string uci_get(const std::string& path);

        void uci_set(const std::string& path, const std::string& value);

        std::string get_hostname()   { return exec("uname -n"); }
        std::string get_interfaces() { return exec("ip link show"); }
        std::string get_wifi_status(){ return exec("iwinfo"); }
    };
}
