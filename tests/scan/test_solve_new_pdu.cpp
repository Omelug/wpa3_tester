#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include "../test_helpers/pcap_helper.h"
#include "config/RunStatus.h"

using namespace std;
using namespace Tins;
using namespace wpa3_tester;

static constexpr auto PCAP_BEACON    = "../test_data/beacon_test.pcapng";
static constexpr auto PCAP_PROBE_RES = "../test_data/probe_res.pcapng";
static constexpr auto PCAP_ASSOC_REQ = "../test_data/assoc_req.pcapng";
static constexpr auto PCAP_DATA_QOS  = "../test_data/wifi_util/data_qos.pcapng";
static constexpr auto PCAP_MULTI     = "../test_data/monitor_socket/radiotap_multi.pcapng";

// beacon_test.pcapng: AP 24:ec:99:bf:b0:a1, SSID "mc_mitm_test", ch6/2437MHz, -28dBm, 2.4GHz
// probe_res.pcapng:   AP 24:ec:99:bf:e0:cd (probe response)
// assoc_req.pcapng:   STA 24:ec:99:bf:e0:cd -> AP 78:98:e8:55:3e:8d
// data_qos.pcapng:    to_ds=1, STA 24:ec:99:bf:e0:cd -> AP 78:98:e8:55:3e:8d

TEST_SUITE("solve_new_pdu beacon") {

	TEST_CASE("beacon adds AP entry to seen map") {
		auto frames = test_helpers::read_all_frames(PCAP_BEACON);
		REQUIRE_FALSE(frames.empty());
		ActorMACMap seen;
		AssocMap assoc;

		RunStatus::solve_new_pdu(frames[0], seen, assoc);

		const HWAddress<6> ap_mac("24:ec:99:bf:b0:a1");
		REQUIRE_EQ(seen.size(), 1u);
		REQUIRE(seen.contains(ap_mac));
		CHECK(seen.at(ap_mac)[BK::AP].value_or(false));
		CHECK_FALSE(seen.at(ap_mac)[BK::STA].value_or(true));
	}

	TEST_CASE("beacon fills ssid, channel and band") {
		auto frames = test_helpers::read_all_frames(PCAP_BEACON);
		REQUIRE_FALSE(frames.empty());
		ActorMACMap seen;
		AssocMap assoc;

		RunStatus::solve_new_pdu(frames[0], seen, assoc);

		const auto &actor = seen.at(HWAddress<6>("24:ec:99:bf:b0:a1"));
		REQUIRE(actor[SK::ssid].has_value());
		CHECK_EQ(actor[SK::ssid].value(), "mc_mitm_test");
		REQUIRE(actor[SK::channel].has_value());
		CHECK_EQ(actor[SK::channel].value(), "6");
		CHECK(actor[BK::GHz2_4].value_or(false));
	}

	TEST_CASE("beacon fills signal strength") {
		auto frames = test_helpers::read_all_frames(PCAP_BEACON);
		REQUIRE_FALSE(frames.empty());
		ActorMACMap seen;
		AssocMap assoc;

		RunStatus::solve_new_pdu(frames[0], seen, assoc);

		const auto &actor = seen.at(HWAddress<6>("24:ec:99:bf:b0:a1"));
		REQUIRE(actor[SK::signal].has_value());
		CHECK_EQ(actor[SK::signal].value(), "-28");
	}

	TEST_CASE("repeated beacon does not duplicate entry") {
		auto frames = test_helpers::read_all_frames(PCAP_BEACON);
		REQUIRE_FALSE(frames.empty());
		ActorMACMap seen;
		AssocMap assoc;

		RunStatus::solve_new_pdu(frames[0], seen, assoc);
		RunStatus::solve_new_pdu(frames[0], seen, assoc);

		CHECK_EQ(seen.size(), 1u);
	}

	TEST_CASE("beacon does not add entry to assoc map") {
		auto frames = test_helpers::read_all_frames(PCAP_BEACON);
		REQUIRE_FALSE(frames.empty());
		ActorMACMap seen;
		AssocMap assoc;

		RunStatus::solve_new_pdu(frames[0], seen, assoc);

		CHECK_EQ(assoc.size(), 0u);
	}
}

TEST_SUITE("solve_new_pdu probe response") {

	TEST_CASE("probe response adds AP to seen map") {
		auto frames = test_helpers::read_all_frames(PCAP_PROBE_RES);
		REQUIRE_FALSE(frames.empty());
		ActorMACMap seen;
		AssocMap assoc;

		RunStatus::solve_new_pdu(frames[0], seen, assoc);

		const HWAddress<6> ap_mac("24:ec:99:bf:e0:cd");
		REQUIRE(seen.contains(ap_mac));
		CHECK(seen.at(ap_mac)[BK::AP].value_or(false));
	}

	TEST_CASE("probe response does not update assoc map") {
		auto frames = test_helpers::read_all_frames(PCAP_PROBE_RES);
		REQUIRE_FALSE(frames.empty());
		ActorMACMap seen;
		AssocMap assoc;

		RunStatus::solve_new_pdu(frames[0], seen, assoc);

		CHECK_EQ(assoc.size(), 0u);
	}
}

TEST_SUITE("solve_new_pdu association request") {

	TEST_CASE("assoc request adds STA to seen map") {
		auto frames = test_helpers::read_all_frames(PCAP_ASSOC_REQ);
		REQUIRE_FALSE(frames.empty());
		ActorMACMap seen;
		AssocMap assoc;

		RunStatus::solve_new_pdu(frames[0], seen, assoc);

		const HWAddress<6> sta_mac("24:ec:99:bf:e0:cd");
		REQUIRE(seen.contains(sta_mac));
	}

	TEST_CASE("assoc request records STA-to-AP association") {
		auto frames = test_helpers::read_all_frames(PCAP_ASSOC_REQ);
		REQUIRE_FALSE(frames.empty());
		ActorMACMap seen;
		AssocMap assoc;

		RunStatus::solve_new_pdu(frames[0], seen, assoc);

		const HWAddress<6> sta_mac("24:ec:99:bf:e0:cd");
		const HWAddress<6> ap_mac("78:98:e8:55:3e:8d");
		REQUIRE(assoc.contains(sta_mac));
		CHECK_EQ(assoc.at(sta_mac), ap_mac);
	}
}

TEST_SUITE("solve_new_pdu data frame") {

	TEST_CASE("to-DS data frame adds STA and AP") {
		auto frames = test_helpers::read_all_frames(PCAP_DATA_QOS);
		REQUIRE_FALSE(frames.empty());
		ActorMACMap seen;
		AssocMap assoc;

		RunStatus::solve_new_pdu(frames[0], seen, assoc);

		const HWAddress<6> sta_mac("24:ec:99:bf:e0:cd");
		const HWAddress<6> ap_mac("78:98:e8:55:3e:8d");
		REQUIRE(seen.contains(sta_mac));
		REQUIRE(seen.contains(ap_mac));
		CHECK_FALSE(seen.at(sta_mac)[BK::AP].value_or(true));
		CHECK(seen.at(ap_mac)[BK::AP].value_or(false));
	}

	TEST_CASE("to-DS data frame records STA-to-AP association") {
		auto frames = test_helpers::read_all_frames(PCAP_DATA_QOS);
		REQUIRE_FALSE(frames.empty());
		ActorMACMap seen;
		AssocMap assoc;

		RunStatus::solve_new_pdu(frames[0], seen, assoc);

		const HWAddress<6> sta_mac("24:ec:99:bf:e0:cd");
		const HWAddress<6> ap_mac("78:98:e8:55:3e:8d");
		REQUIRE(assoc.contains(sta_mac));
		CHECK_EQ(assoc.at(sta_mac), ap_mac);
	}
}

TEST_SUITE("solve_new_pdu edge cases") {

	TEST_CASE("empty packet does not crash") {
		ActorMACMap seen;
		AssocMap assoc;
		constexpr vector<uint8_t> empty;

		CHECK_NOTHROW(RunStatus::solve_new_pdu(empty, seen, assoc));
		CHECK_EQ(seen.size(), 0u);
	}

	TEST_CASE("garbage bytes do not crash") {
		ActorMACMap seen;
		AssocMap assoc;
		const vector<uint8_t> garbage = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF, 0xAA};

		CHECK_NOTHROW(RunStatus::solve_new_pdu(garbage, seen, assoc));
		CHECK_EQ(seen.size(), 0u);
	}

	TEST_CASE("multi-frame pcap accumulates actors across frames") {
		const auto frames = test_helpers::read_all_frames(PCAP_MULTI);
		REQUIRE_FALSE(frames.empty());
		ActorMACMap seen;
		AssocMap assoc;

		for(const auto &frame: frames)
			RunStatus::solve_new_pdu(frame, seen, assoc);

		CHECK_GT(seen.size(), 0u);
	}

	TEST_CASE("broadcast and multicast MACs are filtered out") {
		// beacon addr1 is ff:ff:ff:ff:ff:ff — must not appear in seen
		auto frames = test_helpers::read_all_frames(PCAP_BEACON);
		REQUIRE_FALSE(frames.empty());
		ActorMACMap seen;
		AssocMap assoc;

		RunStatus::solve_new_pdu(frames[0], seen, assoc);

		CHECK_FALSE(seen.contains(HWAddress<6>("ff:ff:ff:ff:ff:ff")));
	}
}
