#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "attacks/DoS_hard/cookie_guzzler/capture_commit_values.h"
#include "pcap_helper.h"

using namespace std;
using namespace Tins;
using namespace wpa3_tester::cookie_guzzler;

const vector<uint8_t> expected_scalar =
{0xcd, 0x3a, 0x57, 0x89, 0xa1, 0x86, 0xa7, 0xae, 0x9f, 0x2d, 0xcc, 0xb1, 0x6a, 0x70, 0xc9, 0xaf,
0xc7, 0xb4, 0x7c, 0xb0, 0x7e, 0x51, 0x9f, 0x66, 0x1f, 0xb3, 0xe9, 0x5, 0x8d, 0xb2, 0x1a, 0xb4};

const vector<uint8_t> expected_element =
{0xeb, 0x90, 0x1b, 0xf1, 0xf2, 0xcd, 0x4a, 0x61, 0x75, 0xa5, 0x14, 0xdf, 0xaf, 0x49, 0xf9, 0x13,
0x33, 0x54, 0x43, 0x86, 0xc8, 0x57, 0x8d, 0xce, 0xe7, 0x9f, 0x17, 0x6e, 0xb7, 0x30, 0x43, 0x38,
0xbe, 0xe0, 0x10, 0xc, 0x72, 0x63, 0xb5, 0xf6, 0xa3, 0x67, 0x24, 0xc7, 0x59, 0xa7, 0x29, 0x9f,
0x51, 0x9a, 0xa3, 0x8f, 0xa7, 0x64, 0xc5, 0xae, 0xe4, 0xa2, 0xf4, 0x5f, 0xb5, 0xe7, 0x21, 0x32};

TEST_CASE("ParsesCommitFromPcap") {
    // Use the real pcap file
    filesystem::path pcap_path = filesystem::path(PROJECT_ROOT_DIR) /
        "../tests/attacks/DoS_hard/cookie_guzzler/test_sae_commit.pcapng";
    vector<uint8_t> probe_data = wpa3_tester::test_helpers::read_pcap_file(pcap_path.string());
    optional<wpa3_tester::dos_helpers::SAEPair> result
        = wpa3_tester::dos_helpers::parse_sae_commit(probe_data.data(), probe_data.size());

    REQUIRE(result.has_value());
    CHECK_EQ(result->scalar.size(), 32);
    CHECK_EQ(result->scalar, expected_scalar);
    CHECK_EQ(result->element.size(), 64);
    CHECK_EQ(result->element, expected_element);
}

//TODO add test for anticlogging
// Add test for packet with/without FCS

// ------------ make_sae_commit test ------------------
TEST_CASE("make_sae_commit - base"){
    RadioTap rt;
    {
        wpa3_tester::dos_helpers::SAEPair sae_params;
        sae_params.scalar = expected_scalar;
        sae_params.element = expected_element;
        sae_params.status = 0;

        const auto ap_mac = HWAddress<6>("11:22:33:44:55:66");
        const auto sta_mac = HWAddress<6>("AA:BB:Cc:DD:EE:FF");
        rt = wpa3_tester::dos_helpers::make_sae_commit(ap_mac, sta_mac, sae_params);
    }
    CHECK_EQ(rt.pdu_type(), Dot11::RADIOTAP);
    Dot11Authentication auth;
    CHECK_NOTHROW(auth = rt.rfind_pdu<Dot11Authentication>());

    CHECK_EQ(auth.addr1(), HWAddress<6>("11:22:33:44:55:66"));
    CHECK_EQ(auth.addr2(), HWAddress<6>("AA:BB:CC:DD:EE:FF"));
    CHECK_EQ(auth.addr3(), HWAddress<6>("11:22:33:44:55:66"));
    CHECK_EQ(auth.subtype(), Dot11::AUTH);

    auto raw = rt.serialize();
    auto result = wpa3_tester::dos_helpers::parse_sae_commit(raw.data(), raw.size());

    REQUIRE(result.has_value());
    CHECK_EQ(result->scalar.size(), 32);
    CHECK_EQ(result->scalar, expected_scalar);
    CHECK_EQ(result->element.size(), 64);
    CHECK_EQ(result->element, expected_element);
    std::vector<uint8_t> empty = {};
    CHECK_EQ(result->token, empty);

}