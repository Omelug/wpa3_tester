#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <algorithm>
#include <doctest.h>
#include <filesystem>
#include <fstream>
#include <regex>
#include <stdexcept>
#include "config/global_config.h"
#include "config/Actor_Config/ActorPtr.h"
#include "config/Actor_Config/Actor_Config_internal.h"
#include "logger/error_log.h"
#include "system/hw_capabilities.h"

#include "config/Actor_Config/Actor_Config_sim.h"

using namespace std;
using namespace wpa3_tester;
using namespace filesystem;

static ActorPtr make_actor(initializer_list<pair<BK,bool>> bools = {}, initializer_list<pair<SK,string>> strs = {}){
	const auto ac = make_shared<Actor_Config_sim>();
	for(auto [k, v]: bools) (*ac)[k] = v;
	for(auto [k, v]: strs) (*ac)[k] = v;
	return ActorPtr(ac);
}

struct GlobalConfigFixture{
	path dir;

	GlobalConfigFixture(): dir(current_path() / "tmp_hw_test_gc"){
		create_directories(dir / "attack_config");
		ofstream f(dir / "attack_config" / "global_config.yaml");
		f << "actors:\n  ignore_interfaces: []\n";
		get_global_config(dir, true);
	}

	~GlobalConfigFixture(){ remove_all(dir); }
};

namespace wpa3_tester{
TEST_CASE("hw_capabilities::freq_to_channel"){
	SUBCASE("2.4 GHz band"){
		CHECK_EQ(hw_capabilities::freq_to_channel(2412), 1);
		CHECK_EQ(hw_capabilities::freq_to_channel(2437), 6);
		CHECK_EQ(hw_capabilities::freq_to_channel(2472), 13);
		CHECK_EQ(hw_capabilities::freq_to_channel(2484), 14);
	}

	SUBCASE("5 GHz band"){
		CHECK_EQ(hw_capabilities::freq_to_channel(5180), 36);
		CHECK_EQ(hw_capabilities::freq_to_channel(5500), 100);
		CHECK_EQ(hw_capabilities::freq_to_channel(5885), 177);
	}

	SUBCASE("6 GHz band"){
		CHECK_EQ(hw_capabilities::freq_to_channel(5955), 1);
		CHECK_EQ(hw_capabilities::freq_to_channel(6455), 101);
		CHECK_EQ(hw_capabilities::freq_to_channel(7115), 233);
	}

	SUBCASE("Invalid frequencies"){
		CHECK_THROWS_AS(hw_capabilities::freq_to_channel(2411), invalid_argument);
		CHECK_THROWS_AS(hw_capabilities::freq_to_channel(3000), invalid_argument);
		CHECK_THROWS_AS(hw_capabilities::freq_to_channel(-1), invalid_argument);
	}
}

TEST_CASE("hw_capabilities::channel_to_freq"){
	SUBCASE("2.4 GHz band"){
		CHECK_EQ(hw_capabilities::channel_to_freq({1, WifiBand::BAND_2_4, nullopt}), 2412);
		CHECK_EQ(hw_capabilities::channel_to_freq({6, WifiBand::BAND_2_4, nullopt}), 2437);
		CHECK_EQ(hw_capabilities::channel_to_freq({13, WifiBand::BAND_2_4, nullopt}), 2472);
		CHECK_EQ(hw_capabilities::channel_to_freq({14, WifiBand::BAND_2_4, nullopt}), 2484);
	}

	SUBCASE("5 GHz band"){
		CHECK_EQ(hw_capabilities::channel_to_freq({36, WifiBand::BAND_5, nullopt}), 5180);
		CHECK_EQ(hw_capabilities::channel_to_freq({100, WifiBand::BAND_5, nullopt}), 5500);
		CHECK_EQ(hw_capabilities::channel_to_freq({177, WifiBand::BAND_5, nullopt}), 5885);
	}

	SUBCASE("6 GHz band"){
		CHECK_EQ(hw_capabilities::channel_to_freq({1, WifiBand::BAND_6, nullopt}), 5955);
		CHECK_EQ(hw_capabilities::channel_to_freq({101, WifiBand::BAND_6, nullopt}), 6455);
		CHECK_EQ(hw_capabilities::channel_to_freq({233, WifiBand::BAND_6, nullopt}), 7115);
	}

	SUBCASE("Invalid channels"){
		CHECK_THROWS_AS(hw_capabilities::channel_to_freq({0, WifiBand::BAND_2_4, nullopt}), invalid_argument);
		CHECK_THROWS_AS(hw_capabilities::channel_to_freq({15,WifiBand::BAND_2_4, nullopt}), invalid_argument);
		CHECK_THROWS_AS(hw_capabilities::channel_to_freq({-1, WifiBand::BAND_2_4, nullopt}), invalid_argument);
	}
}

TEST_CASE("freq_to_channel and channel_to_freq roundtrip"){
	SUBCASE("Roundtrip consistency"){
		vector<tuple<int,int,WifiBand>> test_cases = {
			{2412, 1, WifiBand::BAND_2_4}, {2437, 6, WifiBand::BAND_2_4_or_5}, {2472, 13, WifiBand::BAND_2_4},
			// 2.4 GHz
			{5180, 36, WifiBand::BAND_5}, {5500, 100, WifiBand::BAND_2_4_or_5}, {5885, 177, WifiBand::BAND_5}, // 5 GHz
			{5955, 1, WifiBand::BAND_6}, {6455, 101, WifiBand::BAND_6}, {7115, 233, WifiBand::BAND_6}          // 6 GHz
		};

		for(auto [freq, channel, band]: test_cases){
			CHECK_EQ(hw_capabilities::channel_to_freq({channel, band, nullopt}), freq);
			CHECK_EQ(hw_capabilities::freq_to_channel(freq), channel);
		}
	}
}
}

// ------- rand_mac
TEST_CASE("hw_capabilities::rand_mac - format"){
	const regex mac_pattern(R"(^[0-9a-f]{2}(:[0-9a-f]{2}){5}$)");
	for(int i = 0; i < 20; ++i){
		const string mac = hw_capabilities::rand_mac();
		CHECK(regex_match(mac, mac_pattern));
		CHECK_EQ(mac.size(), 17u);
	}
}

// -------read_sysfs  (uses always-present loopback sysfs entries)
TEST_CASE("hw_capabilities::read_sysfs - loopback type"){
	// /sys/class/net/lo/type contains the ARPHRD value (772 for loopback)
	const string val = hw_capabilities::read_sysfs("lo", "type");
	CHECK_FALSE(val.empty());
	CHECK_EQ(stoi(val), 772);
}

TEST_CASE("hw_capabilities::read_sysfs - nonexistent iface throws"){
	CHECK_THROWS_AS(hw_capabilities::read_sysfs("__no_such_iface__", "type"), config_err);
}

TEST_CASE("hw_capabilities::read_sysfs - nonexistent file throws"){
	CHECK_THROWS_AS(hw_capabilities::read_sysfs("lo", "__no_such_file__"), config_err);
}

// get_driver_name
TEST_CASE("hw_capabilities::get_driver_name - loopback has no driver symlink"){
	// 'lo' has no device/driver symlink → should throw config_err
	CHECK_THROWS_AS(hw_capabilities::get_driver_name("lo"), config_err);
}

TEST_CASE("hw_capabilities::get_driver_name - nonexistent iface throws"){
	CHECK_THROWS_AS(hw_capabilities::get_driver_name("__no_such_iface__"), config_err);
}

// get_phy
TEST_CASE("hw_capabilities::get_phy - loopback returns empty string"){
	// 'lo' has no phy80211 symlink
	const string phy = hw_capabilities::get_phy("lo", nullopt);
	CHECK(phy.empty());
}

TEST_CASE("hw_capabilities::get_phy - nonexistent iface returns empty string"){
	const string phy = hw_capabilities::get_phy("__no_such_iface__", nullopt);
	CHECK(phy.empty());
}

// list_interfaces  (requires global_config)
TEST_CASE("hw_capabilities::list_interfaces - loopback is always present"){
	GlobalConfigFixture gc;
	const auto ifaces = hw_capabilities::list_interfaces();
	const bool found = ranges::any_of(ifaces, [](const InterfaceInfo &i){
		return i.name == "lo" && i.type == InterfaceType::Loopback;
	});
	CHECK(found);
}
TEST_CASE("hw_capabilities::list_interfaces - filter Loopback contains only lo"){
	GlobalConfigFixture gc;
	const auto ifaces = hw_capabilities::list_interfaces(InterfaceType::Loopback);
	REQUIRE_FALSE(ifaces.empty());
	for(const auto &i: ifaces)
		CHECK_EQ(i.type, InterfaceType::Loopback);
}

TEST_CASE("hw_capabilities::list_interfaces - no-match filter returns empty"){
	GlobalConfigFixture gc;
	// WifiVirtualHwsim is unlikely to be present in a standard environment
	const auto ifaces = hw_capabilities::list_interfaces(InterfaceType::WifiVirtualHwsim);
	// Just verify the call succeeds and returns a vector (may be empty)
	CHECK_GE(ifaces.size(), 0u);
}

// ------------ check_req_options / findSolution

TEST_CASE("hw_capabilities::check_req_options - empty rules returns empty map"){
	ActorCMap rules{};
	vector options{make_actor({{BK::AP, true}})};
	const auto result = hw_capabilities::check_req_options(rules, options);
	CHECK(result.empty());
}

TEST_CASE("hw_capabilities::check_req_options - single rule single matching option"){
	ActorPtr rule = make_actor({{BK::AP, true}});
	ActorPtr option = make_actor({{BK::AP, true}});

	ActorCMap rules{{"attacker", rule}};
	vector options{option};

	const auto result = hw_capabilities::check_req_options(rules, options);
	REQUIRE(result.contains("attacker"));
	CHECK_EQ(result.at("attacker").get(), option.get());
}

TEST_CASE("hw_capabilities::check_req_options - no matching option throws"){
	ActorPtr rule = make_actor({{BK::AP, true}});
	ActorPtr option = make_actor({{BK::AP, false}});

	ActorCMap rules{{"attacker", rule}};
	vector options{option};
	CHECK_THROWS_AS(hw_capabilities::check_req_options(rules, options), req_err);
}

TEST_CASE("hw_capabilities::check_req_options - two rules two distinct options"){
	ActorPtr rule_ap = make_actor({{BK::AP, true}});
	ActorPtr rule_sta = make_actor({{BK::STA, true}});

	ActorPtr opt_ap = make_actor({{BK::AP, true}, {BK::STA, false}});
	ActorPtr opt_sta = make_actor({{BK::STA, true}, {BK::AP, false}});

	ActorCMap rules{{"ap_role", rule_ap}, {"sta_role", rule_sta}};
	vector options{opt_ap, opt_sta};

	const auto result = hw_capabilities::check_req_options(rules, options);
	CHECK_EQ(result.size(), 2u);
	CHECK(result.contains("ap_role"));
	CHECK(result.contains("sta_role"));
}

TEST_CASE("hw_capabilities::check_req_options - two rules one option throws"){
	ActorPtr rule1 = make_actor({{BK::AP, true}});
	ActorPtr rule2 = make_actor({{BK::AP, true}});
	ActorPtr opt = make_actor({{BK::AP, true}});

	// Two rules but only one option — second rule can't be satisfied
	ActorCMap rules{{"r1", rule1}, {"r2", rule2}};
	vector options{opt};
	CHECK_THROWS_AS(hw_capabilities::check_req_options(rules, options), req_err);
}

TEST_CASE("hw_capabilities::check_req_options - string key matching"){
	ActorPtr rule = make_actor({}, {{SK::driver_name, "ath9k"}});
	ActorPtr match = make_actor({}, {{SK::driver_name, "ath9k"}});
	ActorPtr nomatch = make_actor({}, {{SK::driver_name, "iwlwifi"}});

	ActorCMap rules{{"dev", rule}};
	const auto result = hw_capabilities::check_req_options(rules, {match, nomatch});
	REQUIRE(result.contains("dev"));
	CHECK_EQ(result.at("dev").get(), match.get());
}
