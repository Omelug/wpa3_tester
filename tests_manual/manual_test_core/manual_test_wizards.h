#pragma once
#include <string>
#include <vector>
#include "ex_program/external_actors/openwrt/OpenWrtConn.h"
#include "system/wifi_channel.h"

namespace wpa3_tester::manual_tests{
void cli_section(const std::string &section_title);
std::unique_ptr<std::string> get_iface_wizard();
std::string get_openwrt_iface_wizard(const OpenWrtConn *conn);
int get_2_4_channel_wizard();

struct TargetInfo{
    std::string bssid;
    std::string ssid;
    Channel channel;
};

TargetInfo get_target_wizard(const std::string &iface, const Channel &channel);
void print_external_entities(const std::vector<ActorPtr> &entities);
bool ask_ok(const std::string &question);
ActorPtr wb_actor_selection();

class manual_test_err: public run_err{
public:
    explicit manual_test_err(const std::string &message): run_err(message){}
};
}