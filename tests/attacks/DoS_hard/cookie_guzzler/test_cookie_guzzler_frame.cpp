#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <tins/tins.h>
#include "attacks/DoS_hard/cookie_guzzler/cookie_guzzler.h"

using namespace std;
using namespace Tins;
using namespace wpa3_tester::cookie_guzzler;

namespace wpa3_tester {
    TEST_CASE("get_cookie_guzzler_frame - creates valid 802.11 Authentication frame") {
        const HWAddress<6> ap_mac("00:11:22:33:44:55");
        const HWAddress<6> sta_mac("AA:BB:CC:DD:EE:FF");
        
        SAEPair sae_params;
        sae_params.scalar = {0x01, 0x02, 0x03, 0x04};
        sae_params.element = {0x05, 0x06, 0x07, 0x08};
        sae_params.success = true;

        RadioTap frame = get_cookie_guzzler_frame(ap_mac, sta_mac, sae_params);


        // Verify 802.11 layer
        const Dot11Authentication* auth = frame.find_pdu<Dot11Authentication>();
        REQUIRE((auth != nullptr));

        // Verify frame type and subtype
        CHECK((auth->type() == Dot11::MANAGEMENT));
        CHECK((auth->subtype() == Dot11::AUTH));

        // Verify address fields
        CHECK((auth->addr1() == ap_mac));  // destination (BSSID)
        CHECK((auth->addr2() == sta_mac)); // source
        CHECK((auth->addr3() == ap_mac));  // BSSID

        // Verify authentication fields
        CHECK((auth->auth_algorithm() == 3));  // SAE algorithm
        CHECK((auth->auth_seq_number() == 1)); // commit sequence
        CHECK((auth->status_code() == 0));

        // Verify payload contains SAE parameters
        const RawPDU* raw_pdu = auth->find_pdu<RawPDU>();
        REQUIRE((raw_pdu != nullptr));
        
        auto payload = raw_pdu->payload();
        REQUIRE((payload.size() == 8));  // 4 bytes scalar + 4 bytes element
        
        // Check scalar part
        for (size_t i = 0; i < 4; ++i) { CHECK((payload[i] == sae_params.scalar[i])); }
        
        // Check element part
        for (size_t i = 0; i < 4; ++i) { CHECK((payload[i + 4] == sae_params.element[i]));}
    }

    TEST_CASE("get_cookie_guzzler_frame - handles empty SAE parameters") {
        const HWAddress<6> ap_mac("00:11:22:33:44:55");
        const HWAddress<6> sta_mac("AA:BB:CC:DD:EE:FF");
        
        SAEPair empty_sae_params;
        empty_sae_params.success = false;

        RadioTap frame = get_cookie_guzzler_frame(ap_mac, sta_mac, empty_sae_params);

        const Dot11Authentication* auth = frame.find_pdu<Dot11Authentication>();
        REQUIRE((auth != nullptr));

        const RawPDU* raw_pdu = auth->find_pdu<RawPDU>();
        REQUIRE((raw_pdu != nullptr));

        auto payload = raw_pdu->payload();
        CHECK(payload.empty());
    }
}
