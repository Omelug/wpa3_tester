#pragma once
#include <string>
#include <vector>
#include <stdexcept>
#include "config/RunStatus.h"
#include "ex_program/external_actors/openwrt/OpenWrtConn.h"

namespace wpa3_tester::manual_tests {
    void cli_section(const std::string& section_title);
    std::string get_iface_wizard();
    std::string get_openwrt_iface_wizard(OpenWrtConn* conn);
    void print_external_entities(const std::vector<ExternalEntity>& entities);
    bool ask_ok(const std::string& question);
    ActorPtr wb_actor_selection();

    class manual_test_err : public std::runtime_error {
    public:
        explicit manual_test_err(const std::string& message) : std::runtime_error(message) {}
    };
}
