#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "stub_two_iface.h"

using namespace wpa3_tester;
using json = nlohmann::json;

TEST_CASE_FIXTURE(TwoIfaceCacheFixture, "validate - throw_on_miss with no cache") {
    CHECK_THROWS_AS(iface.validate(a1, a2, throw_on_miss), req_err);
}

TEST_CASE_FIXTURE(TwoIfaceCacheFixture, "validate - run_on_miss calls run, second call hits cache") {
    iface.run_result = {{"x", 9}};
    const auto [r1, from_cache1] = iface.validate(a1, a2, run_on_miss);
    CHECK_EQ(iface.run_count, 1);
    CHECK_FALSE(from_cache1);
    CHECK_EQ(r1["x"].get<int>(), 9);

    const auto [r2, from_cache2] = iface.validate(a1, a2, run_on_miss);
    CHECK_EQ(iface.run_count, 1); // no second run
    CHECK(from_cache2);
    CHECK_EQ(r2["x"].get<int>(), 9);
}

TEST_CASE_FIXTURE(TwoIfaceCacheFixture, "validate - force_run always calls run regardless of cache") {
    iface.validate(a1, a2, force_run);
    iface.validate(a1, a2, force_run);
    CHECK_EQ(iface.run_count, 2);
}

TEST_CASE_FIXTURE(TwoIfaceCacheFixture, "validate - different actor pairs produce independent cache entries") {
    iface.run_result = {{"pair", "12"}};
    iface.validate(a1, a2, force_run);
    iface.run_result = {{"pair", "21"}};
    iface.validate(a2, a1, force_run);

    const auto [r12, fc12] = iface.validate(a1, a2, throw_on_miss);
    const auto [r21, fc21] = iface.validate(a2, a1, throw_on_miss);
    CHECK_EQ(r12["pair"], "12");
    CHECK_EQ(r21["pair"], "21");
}
