#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <algorithm>
#include <tins/hw_address.h>
#include "config/Actor_Config/Actor_Config_sim.h"
#include "config/Actor_Config/ActorPtr.h"

using namespace std;
using namespace wpa3_tester;

// -----------------

class SimTestable : public Actor_Config_sim {
public:
    using Actor_Config_sim::Actor_Config_sim;

    mutable vector<string> calls;

    void cleanup()                               const override { calls.push_back("cleanup"); }
    void set_iface_up()                          const override { calls.push_back("set_iface_up"); }
    void set_iface_down()                        const override { calls.push_back("set_iface_down"); }
    void up_sniff_iface()                        const override { calls.push_back("up_sniff_iface"); }
    void set_ap_mode()                           const override { calls.push_back("set_ap_mode"); }
    void set_managed_mode()                      const override { calls.push_back("set_managed_mode"); }
    void set_monitor_mode()                      const override { calls.push_back("set_monitor_mode"); }
    void create_sniff_iface()                    const override { calls.push_back("create_sniff_iface"); }
    void set_mac_address(const Tins::HWAddress<6> &mac) const override {
        calls.push_back("set_mac_address:" + mac.to_string());
    }
    void set_channel(const Channel &ch) const override {
        calls.push_back("set_channel:" + to_string(ch.ch_num));
    }

    bool called(const string &what) const {
        return ranges::find(calls, what) != calls.end();
    }
};

// Minimal real_actor: provides iface + permanent_mac so setup_actor skips hw queries
static ActorPtr make_real(const string &iface = "wlan0",
                           const string &mac   = "aa:bb:cc:dd:ee:ff"){
    auto a = make_shared<Actor_Config_sim>();
    a->set(SK::iface,         iface);
    a->set(SK::mac,           mac);
    a->set(SK::permanent_mac, mac);
    return ActorPtr(a);
}

static nlohmann::json make_cfg(const string &name, nlohmann::json actor_json = {}){
    return {{"actors", {{name, actor_json}}}};
}

// -----------------

TEST_CASE("setup_actor sim - change mac address"){
    SimTestable actor;
    actor.set(SK::actor_name,   "sta");
    actor.set(SK::mac,          "bb:cc:dd:ee:ff:00");
    actor.set(SK::permanent_mac,"bb:cc:dd:ee:ff:00");

    actor.setup_actor(make_cfg("sta"), make_real());

    CHECK(actor.called("set_mac_address:bb:cc:dd:ee:ff:00"));
}

TEST_CASE("setup_actor sim - set to AP"){
    SimTestable actor;
    actor.set(SK::actor_name,    "ap");
    actor.set(SK::permanent_mac, "aa:bb:cc:dd:ee:ff");
    actor.set(BK::AP, true);

    actor.setup_actor(make_cfg("ap"), make_real());

    CHECK(actor.called("set_ap_mode"));
    CHECK_FALSE(actor.called("set_managed_mode"));
}

TEST_CASE("setup_actor sim - set to managed"){
    SimTestable actor;
    actor.set(SK::actor_name,    "sta");
    actor.set(SK::permanent_mac, "aa:bb:cc:dd:ee:ff");
    actor.set(BK::managed, true);

    actor.setup_actor(make_cfg("sta"), make_real());

    CHECK(actor.called("set_managed_mode"));
    CHECK_FALSE(actor.called("set_ap_mode"));
}

TEST_CASE("setup_actor sim - set to monitor"){
    SimTestable actor;
    actor.set(SK::actor_name,    "mon");
    actor.set(SK::permanent_mac, "aa:bb:cc:dd:ee:ff");
    actor.set(BK::monitor, true);

    actor.setup_actor(make_cfg("mon"), make_real());

    CHECK(actor.called("set_monitor_mode"));
}

TEST_CASE("setup_actor sim - change channel"){
    SimTestable actor;
    actor.set(SK::actor_name,    "sta");
    actor.set(SK::permanent_mac, "aa:bb:cc:dd:ee:ff");
    actor.set(SK::channel,       "36");
    actor.set(BK::GHz5,          true);
    actor.set(BK::monitor,       true);

    actor.setup_actor(make_cfg("sta"), make_real());

    CHECK(actor.called("set_channel:36"));
}

TEST_CASE("setup_actor sim - create sniff iface"){
    SimTestable actor;
    actor.set(SK::actor_name,    "sniffer");
    actor.set(SK::permanent_mac, "aa:bb:cc:dd:ee:ff");

    actor.setup_actor(make_cfg("sniffer", {{"sniff_iface", "wlan0"}}), make_real());

    CHECK(actor.called("create_sniff_iface"));
    CHECK_EQ(actor.get(SK::sniff_iface), "mon_wlan0");
}
