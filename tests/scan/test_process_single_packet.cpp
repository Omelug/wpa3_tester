#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <set>
#include "../test_helpers/pcap_helper.h"
#include "config/Actor_Config/Actor_Config_external.h"
#include "scan_test_helpers.h"

using namespace std;
using namespace Tins;
using namespace wpa3_tester;

// beacon_test.pcapng: AP 24:ec:99:bf:b0:a1, SSID "mc_mitm_test", ch6, 2.4GHz
// data_qos.pcapng:    to_ds=1, STA 24:ec:99:bf:e0:cd -> AP 78:98:e8:55:3e:8d (assoc map filled)

static constexpr auto PCAP_BEACON   = "../test_data/beacon_test.pcapng";
static constexpr auto PCAP_DATA_QOS = "../test_data/wifi_util/data_qos.pcapng";

static ActorCMap make_ap_req(const string &ssid){
	const auto cfg = make_shared<Actor_Config_external>();
	cfg->set(BK::AP, true);
	cfg->set(SK::ssid, ssid);
	return {{"ap", ActorPtr(cfg)}};
}

static ActorCMap make_sta_req(){
	const auto cfg = make_shared<Actor_Config_external>();
	cfg->set(BK::STA, true);
	return {{"sta", ActorPtr(cfg)}};
}

TEST_SUITE("process_single_packet state") {

	TEST_CASE("garbage bytes return false and leave state empty") {
		const vector<uint8_t> garbage = {0xDE, 0xAD, 0xBE, 0xEF};
		ActorMACMap seen;
		AssocMap assoc;
		set<HWAddress<6>> reported;

		CHECK_FALSE(TestableRunStatus::process_single_packet(
			garbage.data(), garbage.size(), seen, assoc, reported, {}, {}));
		CHECK_EQ(seen.size(), 0u);
		CHECK_EQ(reported.size(), 0u);
	}

	TEST_CASE("empty bytes return false and leave state empty") {
		constexpr vector<uint8_t> empty;
		ActorMACMap seen;
		AssocMap assoc;
		set<HWAddress<6>> reported;

		CHECK_FALSE(TestableRunStatus::process_single_packet(
			empty.data(), 0, seen, assoc, reported, {}, {}));
		CHECK_EQ(seen.size(), 0u);
	}

	TEST_CASE("valid beacon adds AP to seen") {
		auto frames = test_helpers::read_all_frames(PCAP_BEACON);
		REQUIRE_FALSE(frames.empty());
		ActorMACMap seen;
		AssocMap assoc;
		set<HWAddress<6>> reported;

		TestableRunStatus::process_single_packet(
			frames[0].data(), frames[0].size(), seen, assoc, reported,
			make_ap_req("mc_mitm_test"), {});

		REQUIRE(seen.contains(HWAddress<6>("24:ec:99:bf:b0:a1")));
		CHECK(seen.at(HWAddress<6>("24:ec:99:bf:b0:a1"))[BK::AP].value_or(false));
	}

	TEST_CASE("first new actor is inserted into reported set") {
		auto frames = test_helpers::read_all_frames(PCAP_BEACON);
		REQUIRE_FALSE(frames.empty());
		ActorMACMap seen;
		AssocMap assoc;
		set<HWAddress<6>> reported;

		TestableRunStatus::process_single_packet(
			frames[0].data(), frames[0].size(), seen, assoc, reported, {}, {});

		CHECK(reported.contains(HWAddress<6>("24:ec:99:bf:b0:a1")));
	}

	TEST_CASE("second call with same beacon does not re-insert into reported") {
		auto frames = test_helpers::read_all_frames(PCAP_BEACON);
		REQUIRE_FALSE(frames.empty());
		ActorMACMap seen;
		AssocMap assoc;
		set<HWAddress<6>> reported;

		TestableRunStatus::process_single_packet(
			frames[0].data(), frames[0].size(), seen, assoc, reported, {}, {});
		const size_t after_first = reported.size();

		TestableRunStatus::process_single_packet(
			frames[0].data(), frames[0].size(), seen, assoc, reported, {}, {});
		CHECK_EQ(reported.size(), after_first);
	}
}

TEST_SUITE("process_single_packet requirements") {

	TEST_CASE("AP requirement matching beacon SSID returns true") {
		auto frames = test_helpers::read_all_frames(PCAP_BEACON);
		REQUIRE_FALSE(frames.empty());
		ActorMACMap seen;
		AssocMap assoc;
		set<HWAddress<6>> reported;

		CHECK(TestableRunStatus::process_single_packet(
			frames[0].data(), frames[0].size(), seen, assoc, reported,
			make_ap_req("mc_mitm_test"), {}));
	}

	TEST_CASE("AP requirement with wrong SSID returns false") {
		auto frames = test_helpers::read_all_frames(PCAP_BEACON);
		REQUIRE_FALSE(frames.empty());
		ActorMACMap seen;
		AssocMap assoc;
		set<HWAddress<6>> reported;

		CHECK_FALSE(TestableRunStatus::process_single_packet(
			frames[0].data(), frames[0].size(), seen, assoc, reported,
			make_ap_req("nonexistent_ssid"), {}));
	}

	TEST_CASE("STA requirement not satisfied by beacon returns false") {
		auto frames = test_helpers::read_all_frames(PCAP_BEACON);
		REQUIRE_FALSE(frames.empty());
		ActorMACMap seen;
		AssocMap assoc;
		set<HWAddress<6>> reported;

		CHECK_FALSE(TestableRunStatus::process_single_packet(
			frames[0].data(), frames[0].size(), seen, assoc, reported,
			make_sta_req(), {}));
	}
}

// ── connection conditions ───────────────────────────────────────────────────

TEST_SUITE("process_single_packet conn_conds") {

	TEST_CASE("satisfied conn_cond (STA->AP from data frame) returns true") {
		// data_qos: to_ds=1, STA 24:ec:99:bf:e0:cd -> AP 78:98:e8:55:3e:8d
		auto frames = test_helpers::read_all_frames(PCAP_DATA_QOS);
		REQUIRE_FALSE(frames.empty());
		ActorMACMap seen;
		AssocMap assoc;
		set<HWAddress<6>> reported;

		ActorCMap actors;
		auto sta_cfg = make_shared<Actor_Config_external>();
		sta_cfg->set(BK::STA, true);
		actors["sta"] = ActorPtr(sta_cfg);
		auto ap_cfg = make_shared<Actor_Config_external>();
		ap_cfg->set(BK::AP, true);
		actors["ap"] = ActorPtr(ap_cfg);

		CHECK(TestableRunStatus::process_single_packet(
			frames[0].data(), frames[0].size(), seen, assoc, reported,
			actors, {{"sta", "ap"}}));
	}

	TEST_CASE("conn_cond referencing absent actor returns false") {
		// beacon only adds AP; no STA in seen, so conn_cond can't be satisfied
		auto frames = test_helpers::read_all_frames(PCAP_BEACON);
		REQUIRE_FALSE(frames.empty());
		ActorMACMap seen;
		AssocMap assoc;
		set<HWAddress<6>> reported;

		CHECK_FALSE(TestableRunStatus::process_single_packet(
			frames[0].data(), frames[0].size(), seen, assoc, reported,
			make_ap_req("mc_mitm_test"), {{"sta", "ap"}}));
	}
}
