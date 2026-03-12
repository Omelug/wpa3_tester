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
        void get_hw_info() const;
        void get_openwrt_info() const;

        explicit OpenWrtConn(Actor_config* actor): ExternalConn(actor) {};
        bool connect() override;
    };
}
