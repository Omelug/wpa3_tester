#pragma once
#include <string>

#include "config/RunStatus.h"
#include "ex_program/external_actors/ExternalConn.h"

namespace wpa3_tester {
    class OpenWrtConn : public ExternalConn {
        void time_fix() const;
        void forward_internet() const;

    public:
        void check_req(RunStatus &rs) const;

        // UCI helpers
        std::string uci_get(const std::string& path) const;
        void uci_set(const std::string& path, const std::string& value) const;

        // Convenience methods
        std::string get_hostname() const { return exec("uname -n"); }
        std::string get_interfaces() const { return exec("ip link show"); }
        std::string get_wifi_status() const { return exec("iwinfo"); }

        //TODO override connect() and set internet and ntp/date
        // Hardware and system info
        void get_hw_info() const;
        void get_openwrt_info() const;
        explicit OpenWrtConn(Actor_config * get);

        bool connect() override;
    };
}
