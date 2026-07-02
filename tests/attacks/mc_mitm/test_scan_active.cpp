#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include "pcap_helper.h"
#include "scan/active/scan_active.h"
#include "config/Actor_Config/Actor_Config_external.h"

using namespace std;
using namespace Tins;
using namespace wpa3_tester;
using namespace wpa3_tester::scan;

// beacon_test.pcapng: beacon, ch6/2437MHz, -29dBm, RSN (SAE only, MFP capable), HT20, no VHT/HE
static constexpr auto PCAP_BEACON = "pcap/beacon_test.pcapng";
// assoc_resp.pcapng: association response, ch1/2412MHz, -50dBm, HT capable, no RSN IE at all
static constexpr auto PCAP_ASSOC_RESP = "pcap/assoc_resp.pcapng";

// -----------------
// apply_radiotap

TEST_CASE("apply_radiotap - sets signal, channel and band from a real beacon frame"){
    auto [hdr, raw] = test_helpers::read_one_frame(PCAP_BEACON);
    RadioTap rt(raw.data(), static_cast<uint32_t>(raw.size()));
    Actor_Config_external cfg;

    apply_radiotap(rt, cfg);

    REQUIRE(cfg[SK::signal].has_value());
    CHECK_EQ(cfg[SK::signal].value(), "-29");
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
