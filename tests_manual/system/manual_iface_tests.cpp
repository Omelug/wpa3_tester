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

struct TestConfig {
    static inline string base_iface = "wlan1";
    static inline int channel = 4;
};

TEST_CASE("iface up down"){
    REQUIRE_NOTHROW(hw_capabilities::set_iface_up(TestConfig::base_iface));
    REQUIRE_NOTHROW(hw_capabilities::set_iface_down(TestConfig::base_iface));
    REQUIRE_NOTHROW(hw_capabilities::set_iface_down(TestConfig::base_iface));
    REQUIRE_NOTHROW(hw_capabilities::set_iface_up(TestConfig::base_iface));
}

TEST_CASE("set wifi type"){
    REQUIRE_NOTHROW(hw_capabilities::set_iface_down(TestConfig::base_iface));

    REQUIRE_NOTHROW(hw_capabilities::set_wifi_type(TestConfig::base_iface, NL80211_IFTYPE_MONITOR));
    REQUIRE_EQ(netlink_helper::query_wifi_iftype(TestConfig::base_iface), NL80211_IFTYPE_MONITOR);

    REQUIRE_NOTHROW(hw_capabilities::set_wifi_type(TestConfig::base_iface, NL80211_IFTYPE_AP));
    REQUIRE_EQ(netlink_helper::query_wifi_iftype(TestConfig::base_iface), NL80211_IFTYPE_AP);

    REQUIRE_NOTHROW(hw_capabilities::set_wifi_type(TestConfig::base_iface, NL80211_IFTYPE_STATION));
    REQUIRE_EQ(netlink_helper::query_wifi_iftype(TestConfig::base_iface), NL80211_IFTYPE_STATION);
}

TEST_CASE("start ap test") {
    const string base_iface = TestConfig::base_iface;
    const string ap_iface   = "ap_" + base_iface;
    const string pcap_path  = string(PROJECT_ROOT_DIR) + "/../tests/attacks/mc_mitm/beacon_test.pcapng";

    log(LogLevel::INFO, "Running test on iface: " + base_iface);

    const auto raw = test_helpers::read_pcap_file(pcap_path);
    RadioTap rt(raw.data(), raw.size());

    REQUIRE_NOTHROW(rt.rfind_pdu<Dot11Beacon>());
    const Dot11Beacon beacon = rt.rfind_pdu<Dot11Beacon>();

    log(LogLevel::INFO, "Beacon loaded, SSID: " + get_ssid(beacon));

    SUBCASE("AP Start and Stop") {
        RunStatus rs;
        REQUIRE_NOTHROW(start_ap(rs, ap_iface, base_iface, TestConfig::channel, beacon));

        stop_ap(ap_iface);
        log(LogLevel::INFO, "AP stopped");
    }
}