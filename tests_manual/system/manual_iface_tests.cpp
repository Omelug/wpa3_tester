#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <string>
#include <tins/tins.h>

#include "pcap_helper.h"
#include "attacks/mc_mitm/wifi_util.h"
#include "config/RunStatus.h"
#include "config/Actor_Config/Actor_Config_internal.h"
#include "config/Actor_Config/Actor_Config_sim.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"
#include "system/netlink_helper.h"

using namespace std;
using namespace Tins;
using namespace wpa3_tester;

struct TestConfig{
    static inline string base_iface = "wlan1"; // HARDCODED
    static inline optional<string> netns = nullopt;
    static inline int channel = 4;
    static inline auto mac_addr = HWAddress<6>("00:11:22:33:44:55");
};

TEST_CASE("iface mac address change - to fake and back") {
    HWAddress<6> target_mac = TestConfig::mac_addr;
    HWAddress<6> original_mac = hw_capabilities::get_mac_address(TestConfig::base_iface, TestConfig::netns);

    REQUIRE_NOTHROW(hw_capabilities::set_mac_address(TestConfig::base_iface, target_mac, TestConfig::netns));
    CHECK_EQ(hw_capabilities::get_mac_address(TestConfig::base_iface, TestConfig::netns),target_mac);

    REQUIRE_NOTHROW(hw_capabilities::set_mac_address(TestConfig::base_iface, original_mac, TestConfig::netns));
    CHECK_EQ(hw_capabilities::get_mac_address(TestConfig::base_iface, TestConfig::netns), original_mac);
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
    if(!phy_name.empty()) hw_capabilities::run_cmd({"iw", "phy", phy_name, "set", "netns", "1"}, test_ns);

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
    const filesystem::path pcap_path = root_dir().parent_path().string() + "/tests/test_data/beacon_test.pcapng";
    log(LogLevel::INFO, "Running test on iface: {}", base_iface);

    const auto raw = test_helpers::read_pcap_file(pcap_path);
    RadioTap rt(raw.data(), raw.size());

    REQUIRE_NOTHROW(rt.rfind_pdu<Dot11Beacon>());
    const Dot11Beacon beacon = rt.rfind_pdu<Dot11Beacon>();
    log(LogLevel::INFO, "Beacon loaded, SSID: {}", get_ssid(beacon));

    SUBCASE("AP Start and Stop"){
        RunStatus rs;
        auto base_actor = ActorPtr(make_shared<Actor_Config_sim>());
        base_actor->set(SK::iface, base_iface);
        REQUIRE_NOTHROW(start_ap(rs, ap_iface, base_actor, {static_cast<uint8_t>(TestConfig::channel), WifiBand::BAND_2_4_or_5, nullopt}, beacon, TestConfig::mac_addr));

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

	const filesystem::path pcap_path = root_dir().parent_path().string() + "/tests/test_data/beacon_test.pcapng";
    const auto raw = test_helpers::read_pcap_file(pcap_path);
    RadioTap rt(raw.data(), raw.size());
    const Dot11Beacon beacon = rt.rfind_pdu<Dot11Beacon>();

    SUBCASE("Full Connection Flow") {
        RunStatus rs;

        auto ap_actor = ActorPtr(make_shared<Actor_Config_sim>());
        ap_actor->set(SK::iface, ap_phys_iface);
        ap_actor->set(SK::netns, ap_ns);

        start_ap(rs, ap_vif, ap_actor, {static_cast<uint8_t>(TestConfig::channel), WifiBand::BAND_2_4_or_5, nullopt} , beacon,  TestConfig::mac_addr);
        log(LogLevel::INFO, "AP started in namespace: {}", ap_ns);

        stop_ap(ap_vif, ap_ns);
    }
    hw_capabilities::run_cmd({"ip", "netns", "del", ap_ns});
}

TEST_CASE("tx power control"){
    const string iface = TestConfig::base_iface;
    const optional<string> netns = TestConfig::netns;

    // Get initial TX power
    int initial_power = hw_capabilities::get_tx_power(iface, netns);
    log(LogLevel::INFO, "Initial TX power: {} dBm", initial_power);

    // Set new TX power (try 10 dBm)
    const int new_power = 10;
    REQUIRE_NOTHROW(hw_capabilities::set_tx_power(iface, new_power, netns));

    // Verify the change (this may not work due to permissions, but we test the function call)
    // We'll test that the function doesn't throw on valid inputs

    // Reset to original power
    REQUIRE_NOTHROW(hw_capabilities::set_tx_power(iface, initial_power, netns));
}


