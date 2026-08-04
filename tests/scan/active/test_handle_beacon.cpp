#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <tins/tins.h>
#include "scan/active/scan_AP.h"

using namespace std;
using namespace wpa3_tester::scan;
using namespace Tins;

TEST_SUITE("handle_beacon") {

    TEST_CASE("handle_beacon processes valid beacon") {
        // mock beacon PDU
        Dot11Beacon beacon;
        beacon.ssid("TestNetwork");
        beacon.addr2(HWAddress<6>("00:11:22:33:44:55"));

    	RSNInformation rsn_info;
        rsn_info.capabilities(0x0001);  // MFP capable
        rsn_info.add_akm_cypher(RSNInformation::PSK);
        rsn_info.add_akm_cypher(RSNInformation::EAP);
        beacon.rsn_information(rsn_info);

    	ScanAP scan_ap;
    	auto result = handle_beacon(beacon, scan_ap, nullopt);

        REQUIRE(result != nullptr);
        REQUIRE(scan_ap.ssid == "TestNetwork");
        REQUIRE(scan_ap.bssid == HWAddress<6>("00:11:22:33:44:55"));
        REQUIRE(scan_ap.rsn.has_value());
        REQUIRE(scan_ap.rsn->capabilities() == 0x0001);
        auto akms = scan_ap.rsn->akm_cyphers();
        REQUIRE(akms.size() == 2);
        REQUIRE(akms[0] == RSNInformation::PSK);
        REQUIRE(akms[1] == RSNInformation::EAP);
    }

    TEST_CASE("handle_beacon handles beacon without RSN") {
        // Create a mock beacon PDU without RSN
        Dot11Beacon beacon;
        beacon.ssid("OpenNetwork");
        beacon.addr2(HWAddress<6>("AA:BB:CC:DD:EE:FF"));

        ScanAP scan_ap;
        auto result = handle_beacon(beacon, scan_ap, nullopt);

    	REQUIRE(result != nullptr);
        REQUIRE(scan_ap.ssid == "OpenNetwork");
        REQUIRE(scan_ap.bssid == HWAddress<6>("AA:BB:CC:DD:EE:FF"));
        REQUIRE_FALSE(scan_ap.rsn.has_value());
    }

    TEST_CASE("handle_beacon rejects non-beacon PDUs") {
        // Create a non-beacon PDU (probe request)
        Dot11ProbeRequest probe_req;
        probe_req.addr2(HWAddress<6>("00:11:22:33:44:55"));

        ScanAP scan_ap;
        auto result = handle_beacon(probe_req, scan_ap, nullopt);
        REQUIRE(result == nullopt);
    }
}
