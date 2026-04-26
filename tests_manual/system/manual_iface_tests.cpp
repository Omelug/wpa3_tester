#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <string>
#include <tins/tins.h>

#include "pcap_helper.h"
#include "attacks/mc_mitm/wifi_util.h"
#include "config/RunStatus.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"
#include "system/netlink_helper.h"

using namespace std;
using namespace Tins;
using namespace wpa3_tester;

struct TestConfig{
    static inline string base_iface = "wlan1";
    static inline optional<string> netns = nullopt;
    static inline int channel = 4;
    static inline string mac_addr = "00:11:22:33:44:55";
};

TEST_CASE("iface mac address change") {
    string target_mac = TestConfig::mac_addr;
    string original_mac = hw_capabilities::get_macaddress(TestConfig::base_iface, TestConfig::netns);

    REQUIRE_NOTHROW(hw_capabilities::set_mac_address(TestConfig::base_iface, target_mac, TestConfig::netns));
    CHECK_EQ(hw_capabilities::get_macaddress(TestConfig::base_iface, TestConfig::netns),target_mac);

    REQUIRE_NOTHROW(hw_capabilities::set_mac_address(TestConfig::base_iface, original_mac, TestConfig::netns));
    CHECK_EQ(hw_capabilities::get_macaddress(TestConfig::base_iface, TestConfig::netns), original_mac);
    hw_capabilities::set_iface_up(TestConfig::base_iface, TestConfig::netns);
}

TEST_CASE("Cross-namespace interface lifecycle") {
    const string test_ns = "temp_test_ns";
    const string iface = TestConfig::base_iface;

    hw_capabilities::run_cmd({"ip", "netns", "del", test_ns});
    REQUIRE_NOTHROW(hw_capabilities::create_ns(test_ns));
    REQUIRE_NOTHROW(hw_capabilities::move_to_netns(iface, test_ns));

    REQUIRE_NOTHROW(hw_capabilities::set_iface_up(iface, test_ns));
    CHECK(netlink_helper::iface_is_up(iface, test_ns));

    REQUIRE_NOTHROW(hw_capabilities::set_iface_down(iface, test_ns));
    CHECK(netlink_helper::iface_is_down(iface, test_ns));

    const string phy_name = hw_capabilities::get_phy(iface, test_ns);
    if(!phy_name.empty()) {
        hw_capabilities::run_cmd({"iw", "phy", phy_name, "set", "netns", "1"}, test_ns);
    }

    hw_capabilities::run_cmd({"ip", "netns", "del", test_ns});
}

TEST_CASE("iface up down"){
    REQUIRE_NOTHROW(hw_capabilities::set_iface_up(TestConfig::base_iface, TestConfig::netns));
    REQUIRE_NOTHROW(hw_capabilities::set_iface_down(TestConfig::base_iface, TestConfig::netns));
    REQUIRE_NOTHROW(hw_capabilities::set_iface_down(TestConfig::base_iface, TestConfig::netns));
    REQUIRE_NOTHROW(hw_capabilities::set_iface_up(TestConfig::base_iface, TestConfig::netns));
}

TEST_CASE("set wifi type"){
    REQUIRE_NOTHROW(hw_capabilities::set_iface_down(TestConfig::base_iface, TestConfig::netns));

    REQUIRE_NOTHROW(hw_capabilities::set_wifi_type(TestConfig::base_iface, NL80211_IFTYPE_MONITOR, TestConfig::netns));
    REQUIRE_EQ(netlink_helper::query_wifi_iftype(TestConfig::base_iface, TestConfig::netns), NL80211_IFTYPE_MONITOR);

    REQUIRE_NOTHROW(hw_capabilities::set_wifi_type(TestConfig::base_iface, NL80211_IFTYPE_AP, TestConfig::netns));
    REQUIRE_EQ(netlink_helper::query_wifi_iftype(TestConfig::base_iface, TestConfig::netns), NL80211_IFTYPE_AP);

    REQUIRE_NOTHROW(hw_capabilities::set_wifi_type(TestConfig::base_iface, NL80211_IFTYPE_STATION, TestConfig::netns));
    REQUIRE_EQ(netlink_helper::query_wifi_iftype(TestConfig::base_iface, TestConfig::netns), NL80211_IFTYPE_STATION);
}

TEST_CASE("start ap test"){
    const string base_iface = TestConfig::base_iface;
    const string ap_iface = "ap_" + base_iface;
    const string pcap_path = string(PROJECT_ROOT_DIR) + "/../tests/attacks/mc_mitm/beacon_test.pcapng";

    log(LogLevel::INFO, "Running test on iface: "+base_iface);

    const auto raw = test_helpers::read_pcap_file(pcap_path);
    RadioTap rt(raw.data(), raw.size());

    REQUIRE_NOTHROW(rt.rfind_pdu<Dot11Beacon>());
    const Dot11Beacon beacon = rt.rfind_pdu<Dot11Beacon>();
    log(LogLevel::INFO, "Beacon loaded, SSID: "+get_ssid(beacon));

    SUBCASE("AP Start and Stop"){
        RunStatus rs;
        auto base_actor = ActorPtr(std::make_shared<Actor_config>());
        base_actor->str_con["iface"] = base_iface;
        REQUIRE_NOTHROW(start_ap(rs, ap_iface, base_actor, TestConfig::channel, beacon, TestConfig::mac_addr));

        stop_ap(ap_iface, nullopt);
        log(LogLevel::INFO, "AP stopped");
    }
}

TEST_CASE("STA connected to AP in different namespaces") {
    const string ap_ns = "ap_ns";

    const string ap_phys_iface = "wlan1";
    const string ap_vif = "ap_vif";

    REQUIRE_NOTHROW(hw_capabilities::create_ns(ap_ns));
    REQUIRE_NOTHROW(hw_capabilities::move_to_netns(ap_phys_iface, ap_ns));

    const string pcap_path = string(PROJECT_ROOT_DIR) + "/../tests/attacks/mc_mitm/beacon_test.pcapng";
    const auto raw = test_helpers::read_pcap_file(pcap_path);
    RadioTap rt(raw.data(), raw.size());
    const Dot11Beacon beacon = rt.rfind_pdu<Dot11Beacon>();

    SUBCASE("Full Connection Flow") {
        RunStatus rs;

        auto ap_actor = ActorPtr(std::make_shared<Actor_config>());
        ap_actor->str_con["iface"] = ap_phys_iface;
        ap_actor->str_con["netns"] = ap_ns;

        start_ap(rs, ap_vif, ap_actor, TestConfig::channel, beacon,  TestConfig::mac_addr);
        log(LogLevel::INFO, "AP started in namespace: {}", ap_ns);

        stop_ap(ap_vif, ap_ns);
    }
    hw_capabilities::run_cmd({"ip", "netns", "del", ap_ns});
}

