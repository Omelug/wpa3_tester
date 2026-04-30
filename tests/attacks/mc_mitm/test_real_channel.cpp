#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <tins/tins.h>
#include "mitm_helpers.h"
#include "attacks/mc_mitm/mc_mitm.h"
#include "pcap_helper.h"

using namespace std;
using namespace Tins;

namespace wpa3_tester{

TEST_SUITE("handle_action_real") {

    TEST_CASE("non-Action management frame returns false"){
        // Beacon is management but subtype=8, not 13
        auto [rt, raw] = test_helpers::load_frame("./pcap/wifi_util/beacon.pcapng");
        auto *dot11 = rt.find_pdu<Dot11>();
        REQUIRE_NE(dot11, nullptr);

        auto m = make_fixture();
        auto ap_mac  = HWAddress<6>("24:ec:99:bf:b0:a1");
        CHECK_FALSE(m->handle_action_real(ap_mac,rt, *dot11));
        CHECK_EQ(m->rogue_send_count, 0);
        CHECK_EQ(m->real_send_count, 0);
    }

    TEST_CASE("encrypted Action from AP returns true") {
        auto [rt, raw] = test_helpers::load_frame("./pcap/wifi_util/action_protected.pcapng");
        auto *dot11 = rt.find_pdu<Dot11>();
        REQUIRE_NE(dot11, nullptr);
        REQUIRE(dot11->wep()); // sanity check: Protected bit must be set

        auto m = make_fixture();
        auto frame_ap_mac  = HWAddress<6>("24:ec:99:bf:e0:cd");
        m->ap_mac = frame_ap_mac;
        CHECK(m->handle_action_real(frame_ap_mac, rt, *dot11));
        CHECK_EQ(m->rogue_send_count, 1);
        CHECK_EQ(m->real_send_count, 0);
    }

    TEST_CASE("SA Query (category=8) from unknown src returns false") {
        auto [rt, raw] = test_helpers::load_frame("./pcap/wifi_util/action_protected.pcapng");
        auto *dot11 = rt.find_pdu<Dot11>();
        REQUIRE_NE(dot11, nullptr);

        auto m = make_fixture(true);
        auto ap_mac  = HWAddress<6>("24:ec:99:bf:b0:FF");
        CHECK_FALSE(m->handle_action_real(ap_mac, rt, *dot11));
        CHECK_EQ(m->rogue_send_count, 0);
        CHECK_EQ(m->real_send_count, 0);
    }
}
}