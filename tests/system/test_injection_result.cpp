#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "system/injection_result.h"

using namespace wpa3_tester;
using namespace nlohmann;
TEST_CASE("it_test_result - json round-trip"){
    CHECK_EQ(json(PASSED), "PASSED");
    CHECK_EQ(json(FAIL), "FAIL");
    CHECK_EQ(json(NOCAPTURE), "NOCAPTURE");
    CHECK_EQ(json(UNKNOWN), "UNKNOWN");

    CHECK_EQ(json("PASSED").get<it_test_result>(), PASSED);
    CHECK_EQ(json("FAIL").get<it_test_result>(), FAIL);
    CHECK_EQ(json("NOCAPTURE").get<it_test_result>(), NOCAPTURE);
    CHECK_EQ(json("bogus").get<it_test_result>(), UNKNOWN);
}

TEST_CASE("InjectionTestResult - to_json"){
    const InjectionTestResult t("csa", FAIL, "no CSA frame captured");
    const auto j = t.to_json();

    CHECK_EQ(j.at("csa").at("result").get<std::string>(), "FAIL");
    CHECK_EQ(j.at("csa").at("detail").get<std::string>(), "no CSA frame captured");
}

TEST_CASE("InjectionSuiteResult - inject_all and to_json"){
    InjectionSuiteResult suite;
    suite.tests.emplace_back("ping", PASSED);
    suite.tests.emplace_back("csa", FAIL, "timeout");

    CHECK_EQ(suite.inject_all(), FAIL);

    const auto j = suite.to_json();
    CHECK_EQ(j.at("tests").at("ping").at("result").get<std::string>(), "PASSED");
    CHECK_EQ(j.at("tests").at("csa").at("result").get<std::string>(), "FAIL");
    CHECK_EQ(j.at("tests").at("csa").at("detail").get<std::string>(), "timeout");
}

TEST_CASE("InjectionSuiteResult - inject_all passes when all tests pass"){
    InjectionSuiteResult suite;
    suite.tests.emplace_back("ping", PASSED);
    suite.tests.emplace_back("csa", PASSED);

    CHECK_EQ(suite.inject_all(), PASSED);
}
