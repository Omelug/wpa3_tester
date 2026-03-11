#pragma once
#include <string>
#include "ex_program/external_actors/ExternalConn.h"

namespace wpa3_tester {
    class OpenWrtConn : public ExternalConn {
    public:
        ~OpenWrtConn() = default;

        // UCI helpers
        std::string uci_get(const std::string& path) const;
        void uci_set(const std::string& path, const std::string& value) const;

        // Convenience methods
        std::string get_hostname() const { return exec("uname -n"); }
        std::string get_interfaces() const { return exec("ip link show"); }
        std::string get_wifi_status() const { return exec("iwinfo"); }

        // Hardware and system info
        void get_hw_info();
        void get_openwrt_info();
        explicit OpenWrtConn(Actor_config * get);
    };
}
