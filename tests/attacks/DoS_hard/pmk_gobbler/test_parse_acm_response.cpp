#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <vector>
#include "pcap_helper.h"
#include "attacks/DoS_hard/PMK_gobbler/pmk_gobbler.h"

using namespace std;
using namespace Tins;
using namespace wpa3_tester::pmk_gobbler;

namespace wpa3_tester {

    TEST_CASE("parse_acm_response - valid ACM commit packet from pcap") {
        char errbuf[PCAP_ERRBUF_SIZE];
        auto frame = test_helpers::read_pcap_file("ACM_commit_test.pcapng");
        auto result = parse_acm_response(frame.data(), frame.size());
        
        REQUIRE(result.has_value());
        const ACMCookie& cookie = result.value();

        //  Receiver address: 78:98:e8:55:3e:8d
        HWAddress<6> expected_sta_mac("78:98:e8:55:3e:8d");
        CHECK_EQ(cookie.sta_mac, expected_sta_mac);
        REQUIRE(!cookie.token.empty());
        // Anti-Clogging Token: 0001d5e6fdae673642ddbb59598404fbf768f848820e3dcaaeffefa1c6d3ace7
        vector<uint8_t> expected_token = {
            0x00, 0x01, 0xd5, 0xe6, 0xfd, 0xae, 0x67, 0x36,
            0x42, 0xdd, 0xbb, 0x59, 0x59, 0x84, 0x04, 0xfb,
            0xf7, 0x68, 0xf8, 0x48, 0x82, 0x0e, 0x3d, 0xca,
            0xae, 0xff, 0xef, 0xa1, 0xc6, 0xd3, 0xac, 0xe7
        };
        CHECK_EQ(cookie.token, expected_token);
    }
}