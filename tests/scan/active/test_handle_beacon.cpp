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

		auto result = handle_beacon(beacon, HWAddress<6>("00:11:22:33:44:55"), nullopt);
		CHECK_NE(result, nullopt);
	}

	TEST_CASE("handle_beacon rejects different MAC") {
		Dot11ProbeRequest probe_req;
		probe_req.addr2(HWAddress<6>("00:11:22:33:44:55"));
		auto result = handle_beacon(probe_req, HWAddress<6>("00:42:22:42:44:42"), nullopt);
		CHECK_EQ(result, nullopt);
	}

	TEST_CASE("handle_beacon rejects non-beacon PDUs") {
		Dot11ProbeRequest probe_req;
		probe_req.addr2(HWAddress<6>("00:11:22:33:44:55"));
		auto result = handle_beacon(probe_req, HWAddress<6>("00:11:22:33:44:55"), nullopt);
		CHECK_EQ(result, nullopt);
	}
}
