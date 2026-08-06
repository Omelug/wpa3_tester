#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include "scan_test_helpers.h"

using namespace std;
using namespace wpa3_tester;

// All tests exercise only JSON config parsing — no hardware access.

TEST_SUITE("get_external_BB_channels - scan_channels key") {

	TEST_CASE("explicit scan_channels list is returned as-is") {
		TestableRunStatus rs;
		rs.set_config({{"scan_channels", {6, 11, 1}}});
		const auto ch = rs.get_external_BB_channels();
		CHECK_EQ(ch, vector<uint8_t>({6, 11, 1}));
	}

	TEST_CASE("empty scan_channels list returns empty") {
		TestableRunStatus rs;
		rs.set_config({{"scan_channels", nlohmann::json::array()}});
		const auto ch = rs.get_external_BB_channels();
		CHECK_EQ(ch.size(), 0u);
	}
}

TEST_SUITE("get_external_BB_channels - actors fallback") {

	TEST_CASE("channels extracted from actors are sorted and deduplicated") {
		TestableRunStatus rs;
		rs.set_config({{"actors", {
			{"ap",  {{"selection", {{"channel", 11}}}}},
			{"sta", {{"selection", {{"channel", 6}}}}},
			{"ap2", {{"selection", {{"channel", 11}}}}}, // duplicate
			{"sta2", {{"selection", {{"ssid", "test"}}}}} // no channel
		}}});
		const auto ch = rs.get_external_BB_channels();
		REQUIRE_EQ(ch.size(), 2u);
		CHECK_EQ(ch[0], 6);
		CHECK_EQ(ch[1], 11);
	}

	TEST_CASE("single actor with channel produces one-element list") {
		TestableRunStatus rs;
		rs.set_config({{"actors", {
			{"ap", {{"selection", {{"channel", 6}}}}}
		}}});
		const auto ch = rs.get_external_BB_channels();
		REQUIRE_EQ(ch.size(), 1u);
		CHECK_EQ(ch[0], 6);
	}
}
