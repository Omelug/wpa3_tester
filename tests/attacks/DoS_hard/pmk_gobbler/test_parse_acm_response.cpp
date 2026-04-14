#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <vector>

#include "attacks/DoS_hard/PMK_gobbler/pmk_gobbler.h"

using namespace std;
using namespace Tins;
using namespace wpa3_tester::pmk_gobbler;

namespace wpa3_tester {

    TEST_CASE("parse_acm_response - valid ACM commit packet from pcap") {
        char errbuf[PCAP_ERRBUF_SIZE];
        string filename = "ACM_commit_test.pcapng";
        pcap_t* handle = pcap_open_offline(filename.c_str(), errbuf);

        pcap_pkthdr* header;
        const u_char* packet;

        pcap_next_ex(handle, &header, &packet);
        vector frame_data(packet, packet + header->caplen);
        pcap_close(handle);

        REQUIRE(!frame_data.empty());
        
        // Test parsing the ACM response
        auto result = parse_acm_response(frame_data.data(), static_cast<uint32_t>(frame_data.size()));
        
        REQUIRE(result.has_value());
        
        const ACMCookie& cookie = result.value();
        
        //  Receiver address: DLinkInterna_55:3e:8d (78:98:e8:55:3e:8d)
        HWAddress<6> expected_sta_mac("78:98:e8:55:3e:8d");
        CHECK_EQ(cookie.sta_mac, expected_sta_mac);
        
        // Check that token is not empty (should contain the anti-clogging token)
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
