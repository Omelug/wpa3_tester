#pragma once

#include "pcap_helper.h"
#include "attacks/mc_mitm/mc_mitm.h"

namespace wpa3_tester{

// Minimal McMitm fixture
constexpr auto AP_MAC  = "11:22:33:44:55:66";
constexpr auto CLIENT_MAC  = "aa:bb:cc:dd:ee:ff";

class McMitmTestable : public McMitm {
public:
    using McMitm::McMitm;
    using McMitm::ap_mac;
    mutable int real_send_count = 0;
    mutable int rogue_send_count = 0;

protected:
    void send_to_real(Tins::PDU &) const override { ++real_send_count; }
    void send_to_rogue(Tins::PDU &) const override { ++rogue_send_count; }
};


static std::unique_ptr<McMitmTestable> make_fixture(const bool with_client = false) {
    const auto r_sta_actor = ActorPtr(std::make_shared<Actor_config>());
    const auto r_ap_actor = ActorPtr(std::make_shared<Actor_config>());

    r_sta_actor->str_con["iface"] = "wlan1";
    r_ap_actor->str_con["iface"] = "wlan2";

    const std::string ap_ssid = "test_mc_mitm";
    auto m = std::make_unique<McMitmTestable>(r_sta_actor, r_ap_actor, ap_ssid, AP_MAC, CLIENT_MAC);
    if(with_client) {
        ClientState cs(CLIENT_MAC);
        cs.update_state(ClientState::GotMitm);
        m->add_client(cs);
    }
    return m;
}
}