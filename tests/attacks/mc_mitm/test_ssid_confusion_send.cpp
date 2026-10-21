#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <tins/tins.h>
#include "attacks/mc_mitm/ssid_confusion/ssid_helper.h"
#include "attacks/mc_mitm/wifi_util.h"
#include "config/Actor_Config/Actor_Config_internal.h"
#include "mitm_helpers.h"

using namespace std;
using namespace Tins;
using namespace wpa3_tester;
using namespace wpa3_tester::ssid_confusion;

namespace {

// Mocks sock_rogue/sock_real sends by intercepting at the raw-frame level.
// ensure_radiotap() still runs; only the actual pcap socket call is bypassed.
class SsidConfusionTestable : public SsidConfusion {
public:
    using SsidConfusion::SsidConfusion;
    // un-hide parent PDU overloads so m->send_to_rogue(dot11_pdu) compiles
    using SsidConfusion::send_to_rogue;
    using SsidConfusion::send_to_real;

    mutable vector<frame_raw_t> rogue_captured;
    mutable vector<frame_raw_t> real_captured;

    void send_to_rogue(const frame_raw_t &raw) const override { rogue_captured.push_back(ensure_radiotap(raw)); }
    void send_to_real(const frame_raw_t &raw) const override  { real_captured.push_back(ensure_radiotap(raw)); }
};

unique_ptr<SsidConfusionTestable> make_ssid_fixture() {
    auto r_sta = ActorPtr(make_shared<Actor_Config_internal>());
    auto r_ap  = ActorPtr(make_shared<Actor_Config_internal>());
    auto sta   = ActorPtr(make_shared<Actor_Config_internal>());
    auto ap    = ActorPtr(make_shared<Actor_Config_internal>());
    r_sta->set(SK::iface, "wlan1");
    r_sta->set(SK::channel, "1");
    r_sta->set(BK::GHz2_4, true);
    r_ap->set(SK::iface, "wlan2");
    r_ap->set(SK::channel, "6");
    r_ap->set(BK::GHz2_4, true);
    sta->set(SK::mac, string(CLIENT_MAC));
    ap->set(SK::mac,  string(AP_MAC));
    ap->set(SK::ssid, "TestNet");
    return make_unique<SsidConfusionTestable>(r_sta, r_ap, sta, ap, nullopt, "SafeNet", 100);
}

}

namespace {
// Return raw bytes with the leading RadioTap header stripped.
// Both send_to_* overloads must receive bare Dot11 bytes for ensure_radiotap
// to produce the same output regardless of which overload is called.
frame_raw_t strip_radiotap(const frame_raw_t &raw) {
    REQUIRE_GE(raw.size(), 4u);
    const uint16_t rt_len = raw[2] | static_cast<uint16_t>(raw[3]) << 8;
    REQUIRE_LE(rt_len, raw.size());
    return {raw.begin() + rt_len, raw.end()};
}
} // namespace

TEST_SUITE("SsidConfusion::send_to_rogue") {

    TEST_CASE("PDU and raw overloads produce identical captured bytes (beacon)") {
        auto m = make_ssid_fixture();
        auto [rt, raw] = test_helpers::load_frame("test_data/wifi_util/beacon.pcapng");
        auto *dot11 = rt.find_pdu<Dot11>();
        REQUIRE_NE(dot11, nullptr);
        const auto dot11_raw = strip_radiotap(raw);

        m->send_to_rogue(*dot11);
        m->send_to_rogue(dot11_raw);

        REQUIRE_EQ(m->rogue_captured.size(), 2);
        CHECK_EQ(m->rogue_captured[0], m->rogue_captured[1]);
    }
}

TEST_SUITE("SsidConfusion::send_to_real") {

    TEST_CASE("PDU and raw overloads produce identical captured bytes (beacon)") {
        auto m = make_ssid_fixture();
        auto [rt, raw] = test_helpers::load_frame("test_data/wifi_util/beacon.pcapng");
        auto *dot11 = rt.find_pdu<Dot11>();
        REQUIRE_NE(dot11, nullptr);
        const auto dot11_raw = strip_radiotap(raw);

        m->send_to_real(*dot11);
        m->send_to_real(dot11_raw);

        REQUIRE_EQ(m->real_captured.size(), 2);
        CHECK_EQ(m->real_captured[0], m->real_captured[1]);
    }
}
