#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include "pcap_helper.h"
#include "scan/active/scan_active.h"
#include "scan/active/scan_STA.h"
#include "config/Actor_Config/Actor_Config_external.h"

using namespace std;
using namespace Tins;
using namespace wpa3_tester;
using namespace wpa3_tester::scan;

// beacon_test.pcapng: beacon, ch6/2437MHz, RSN (SAE only, MFP capable), HT20, no VHT/HE
// transmitter 24:ec:99:bf:b0:a1, SSID "mc_mitm_test"
// NOTE: radiotap has two antennas with different dBm Antenna Signal readings (tshark shows -29,
// but Tins::RadioTap::dbm_signal() parses the other one: -28) — -28 is what apply_radiotap() actually sees.
static constexpr auto PCAP_BEACON = "test_data/beacon_test.pcapng";
// assoc_resp.pcapng: association response (subtype 1), ch1/2412MHz, -50dBm, HT capable, no RSN IE at all
static constexpr auto PCAP_ASSOC_RESP = "test_data/assoc_resp.pcapng";
// assoc_req.pcapng: real association request (subtype 0) extracted from test_data/monitor_socket/radiotap_multi.pcapng
// frame 5, ch1/2412MHz, RSN (SAE only, MFP capable), HT capable (no HT Operation IE), no VHT/HE
// transmitter (station) 24:ec:99:bf:e0:cd
// NOTE: same dual-antenna radiotap quirk as beacon_test.pcapng — tshark shows -44, Tins parses -27.
static constexpr auto PCAP_ASSOC_REQ = "test_data/assoc_req.pcapng";

// -----------------
// apply_radiotap

TEST_CASE("apply_radiotap - sets signal, channel and band from a real beacon frame"){
    auto [hdr, raw] = test_helpers::read_one_frame(PCAP_BEACON);
    RadioTap rt(raw.data(), static_cast<uint32_t>(raw.size()));
    Actor_Config_external cfg;

    apply_radiotap(rt, cfg);

    REQUIRE(cfg[SK::signal].has_value());
    CHECK_EQ(cfg[SK::signal].value(), "-28");
    REQUIRE(cfg[SK::channel].has_value());
    CHECK_EQ(cfg[SK::channel].value(), "6");
    CHECK(cfg[BK::GHz2_4].value_or(false));
}

// -----------------
// apply_rsn

TEST_CASE("apply_rsn - extracts MFP/OCV/beacon_prot and WPA3-SAE from a real beacon frame"){
    auto [hdr, raw] = test_helpers::read_one_frame(PCAP_BEACON);
    RadioTap rt(raw.data(), static_cast<uint32_t>(raw.size()));
    const auto *beacon = rt.find_pdu<Dot11Beacon>();
    REQUIRE_NE(beacon, nullptr);
    Actor_Config_external cfg;

    apply_rsn(*beacon, cfg);

    CHECK(cfg[BK::MFP].value_or(false));
    CHECK_FALSE(cfg[BK::OCV].value_or(false));
    CHECK_FALSE(cfg[BK::beacon_prot].value_or(false));
    CHECK(cfg[BK::WPA3_SAE].value_or(false));
    CHECK_FALSE(cfg[BK::WPA_PSK].has_value()); // only SAE AKM present, PSK never matched
}

TEST_CASE("apply_rsn - frame without an RSN IE logs a warning instead of throwing"){
    auto [hdr, raw] = test_helpers::read_one_frame(PCAP_ASSOC_RESP);
    RadioTap rt(raw.data(), static_cast<uint32_t>(raw.size()));
    const auto *assoc = rt.find_pdu<Dot11AssocResponse>();
    REQUIRE_NE(assoc, nullptr);
    Actor_Config_external cfg;

    CHECK_NOTHROW(apply_rsn(*assoc, cfg));

    CHECK_FALSE(cfg[BK::MFP].has_value());
    CHECK_FALSE(cfg[BK::WPA3_SAE].has_value());
    CHECK_FALSE(cfg[BK::WPA_PSK].has_value());
}

// -----------------
// apply_ht_vht_he

TEST_CASE("apply_ht_vht_he - detects HT20 with no VHT/HE from a real beacon frame"){
    auto [hdr, raw] = test_helpers::read_one_frame(PCAP_BEACON);
    RadioTap rt(raw.data(), static_cast<uint32_t>(raw.size()));
    const auto *beacon = rt.find_pdu<Dot11Beacon>();
    REQUIRE_NE(beacon, nullptr);
    Actor_Config_external cfg;

    apply_ht_vht_he(*beacon, cfg);

    CHECK(cfg[BK::w80211n].value_or(false));
    REQUIRE(cfg[SK::ht_mode].has_value());
    CHECK_EQ(cfg[SK::ht_mode].value(), "HT20");
    CHECK_FALSE(cfg[BK::w80211ac].value_or(true));
    CHECK_FALSE(cfg[BK::w80211ax].value_or(true));
}

TEST_CASE("apply_ht_vht_he - detects HT capability from a real assoc-response frame"){
    auto [hdr, raw] = test_helpers::read_one_frame(PCAP_ASSOC_RESP);
    RadioTap rt(raw.data(), static_cast<uint32_t>(raw.size()));
    const auto *assoc = rt.find_pdu<Dot11AssocResponse>();
    REQUIRE_NE(assoc, nullptr);
    Actor_Config_external cfg;

    apply_ht_vht_he(*assoc, cfg);

    CHECK(cfg[BK::w80211n].value_or(false));
    CHECK_FALSE(cfg[BK::w80211ac].value_or(true));
    CHECK_FALSE(cfg[BK::w80211ax].value_or(true));
}

// -----------------
// fill_actor_caps_from_beacon

TEST_CASE("fill_actor_caps_from_beacon - fills mac/ssid/band/RSN/HT/role from a real beacon"){
    auto [hdr, raw] = test_helpers::read_one_frame(PCAP_BEACON);
    RadioTap rt(raw.data(), static_cast<uint32_t>(raw.size()));
    Actor_Config_external cfg;

    fill_actor_caps_from_beacon(rt, cfg);

    REQUIRE(cfg[SK::mac].has_value());
    CHECK_EQ(cfg[SK::mac].value(), "24:ec:99:bf:b0:a1");
    REQUIRE(cfg[SK::ssid].has_value());
    CHECK_EQ(cfg[SK::ssid].value(), "mc_mitm_test");
    REQUIRE(cfg[SK::channel].has_value());
    CHECK_EQ(cfg[SK::channel].value(), "6");
    CHECK(cfg[BK::GHz2_4].value_or(false));

    CHECK(cfg[BK::MFP].value_or(false));
    CHECK_FALSE(cfg[BK::OCV].value_or(false));
    CHECK(cfg[BK::WPA3_SAE].value_or(false));

    CHECK(cfg[BK::w80211n].value_or(false));
    REQUIRE(cfg[SK::ht_mode].has_value());
    CHECK_EQ(cfg[SK::ht_mode].value(), "HT20");

    CHECK(cfg[BK::AP].value_or(false));
    CHECK_FALSE(cfg[BK::STA].value_or(true));
    CHECK_FALSE(cfg[BK::managed].value_or(true));
    CHECK_FALSE(cfg[BK::monitor].value_or(true));
}

TEST_CASE("fill_actor_caps_from_beacon - non-beacon frame leaves cfg untouched"){
    auto [hdr, raw] = test_helpers::read_one_frame(PCAP_ASSOC_RESP);
    RadioTap rt(raw.data(), static_cast<uint32_t>(raw.size()));
    Actor_Config_external cfg;

    CHECK_NOTHROW(fill_actor_caps_from_beacon(rt, cfg));

    CHECK_FALSE(cfg[SK::mac].has_value());
    CHECK_FALSE(cfg[BK::AP].has_value());
}

// -----------------
// fill_actor_caps_from_assoc_req

TEST_CASE("fill_actor_caps_from_assoc_req - fills mac/band/RSN/HT/role from a real assoc-request"){
    auto [hdr, raw] = test_helpers::read_one_frame(PCAP_ASSOC_REQ);
    RadioTap rt(raw.data(), static_cast<uint32_t>(raw.size()));
    Actor_Config_external cfg;

    fill_actor_caps_from_assoc_req(rt, cfg);

    REQUIRE(cfg[SK::mac].has_value());
    CHECK_EQ(cfg[SK::mac].value(), "24:ec:99:bf:e0:cd");
    REQUIRE(cfg[SK::channel].has_value());
    CHECK_EQ(cfg[SK::channel].value(), "1");
    CHECK(cfg[BK::GHz2_4].value_or(false));
    REQUIRE(cfg[SK::signal].has_value());
    CHECK_EQ(cfg[SK::signal].value(), "-27");

    CHECK(cfg[BK::MFP].value_or(false));
    CHECK_FALSE(cfg[BK::OCV].value_or(false));
    CHECK(cfg[BK::WPA3_SAE].value_or(false));

    CHECK(cfg[BK::w80211n].value_or(false));
    // no HT Operation IE in an assoc-request -> falls back to HT20
    REQUIRE(cfg[SK::ht_mode].has_value());
    CHECK_EQ(cfg[SK::ht_mode].value(), "HT20");
    CHECK_FALSE(cfg[BK::w80211ac].value_or(true));
    CHECK_FALSE(cfg[BK::w80211ax].value_or(true));

    CHECK_FALSE(cfg[BK::AP].value_or(true));
    CHECK(cfg[BK::STA].value_or(false));
    CHECK_FALSE(cfg[BK::managed].value_or(true));
    CHECK_FALSE(cfg[BK::monitor].value_or(true));
}

TEST_CASE("fill_actor_caps_from_assoc_req - subtype guard rejects a real association-response frame"){
    auto [hdr, raw] = test_helpers::read_one_frame(PCAP_ASSOC_RESP);
    RadioTap rt(raw.data(), static_cast<uint32_t>(raw.size()));
    Actor_Config_external cfg;

    CHECK_NOTHROW(fill_actor_caps_from_assoc_req(rt, cfg));

    CHECK_FALSE(cfg[SK::mac].has_value());
    CHECK_FALSE(cfg[BK::STA].has_value());
}
