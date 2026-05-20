#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "stub_two_iface.h"

using namespace wpa3_tester;
using json = nlohmann::json;

TEST_CASE_FIXTURE(TwoIfaceCacheFixture, "make_cache_key - order sensitive") {
	CHECK_NE(iface.make_cache_key(a1, a2), iface.make_cache_key(a2, a1));
}

TEST_CASE_FIXTURE(TwoIfaceCacheFixture, "lookup_cache - miss when file absent") {
    CHECK_FALSE(iface.lookup_cache(iface.make_cache_key(a1, a2)).has_value());
}

TEST_CASE_FIXTURE(TwoIfaceCacheFixture, "write_cache / lookup_cache - roundtrip") {
    const json data = {{"result", 42}};
    const std::string key = iface.make_cache_key(a1, a2);
    iface.write_cache(key, data);
    const auto got = iface.lookup_cache(key);
    REQUIRE(got.has_value());
    CHECK_EQ(*got, data);
}

TEST_CASE_FIXTURE(TwoIfaceCacheFixture, "write_cache - updates existing key in place") {
    const std::string key = iface.make_cache_key(a1, a2);
    iface.write_cache(key, {{"v", 1}});
    iface.write_cache(key, {{"v", 2}});
    const auto got = iface.lookup_cache(key);
    REQUIRE(got.has_value());
    CHECK_EQ(got.value()["v"].get<int>(), 2);
}

TEST_CASE_FIXTURE(TwoIfaceCacheFixture, "write_cache - two distinct keys coexist") {
    const std::string k12 = iface.make_cache_key(a1, a2);
    const std::string k21 = iface.make_cache_key(a2, a1);
    iface.write_cache(k12, {{"dir", "12"}});
    iface.write_cache(k21, {{"dir", "21"}});
    CHECK_EQ(iface.lookup_cache(k12).value()["dir"], "12");
    CHECK_EQ(iface.lookup_cache(k21).value()["dir"], "21");
}
