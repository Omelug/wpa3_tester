#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <nlohmann/json.hpp>
#include "config/Actor_config.h"
#include "logger/error_log.h"

using namespace std;
using namespace wpa3_tester;
using json = nlohmann::json;

TEST_CASE("Actor_config - json constructor with selection"){
    json j = {
        {
            "selection", {
                {"iface", "wlan0"},
                {"driver", "ath9k"},
                {"condition", {"monitor", "injection"}}
            }
        },
        {"netns", "sta"},
    };

    Actor_config actor(j);

    CHECK(actor[SK::iface].has_value());
    CHECK_EQ(actor[SK::iface].value(), "wlan0");
    CHECK(actor[SK::driver].has_value());
    CHECK_EQ(actor[SK::driver].value(), "ath9k");
    CHECK_EQ(actor[SK::netns].value(), "sta");

    CHECK(actor[BK::monitor].value_or(false));
    CHECK(actor[BK::injection].value_or(false));
    CHECK_FALSE((actor[BK::AP].has_value()));
}

TEST_CASE("Actor_config - json constructor without selection"){
    json j = {{"type", "STA"}};

    Actor_config actor(j);

    // Should remain empty/nullopt
    CHECK_FALSE(actor[SK::iface]);
    CHECK_FALSE(actor[BK::monitor]);
}

TEST_CASE("Actor_config - matches method"){
    SUBCASE("Exact match") {
        Actor_config required;
        required[SK::iface] = "wlan0";
        required[BK::monitor] = true;

        Actor_config offer;
        offer[SK::iface] = "wlan0";
        offer[SK::driver] = "ath9k";
        offer[BK::monitor] = true;
        offer[BK::injection] = true;

        CHECK(required.matches(offer));
    }

    SUBCASE("String mismatch") {
        Actor_config required;
        required[SK::iface] = "wlan0";

        Actor_config offer;
        offer[SK::iface] = "wlan1";

        CHECK_FALSE(required.matches(offer));
    }

    SUBCASE("Bool condition mismatch") {
        Actor_config required;
        required[BK::monitor] = true;

        Actor_config offer;
        offer[BK::monitor] = false;

        CHECK_FALSE(required.matches(offer));
    }

    SUBCASE("Offer missing required string") {
        Actor_config required;
        required[SK::iface] = "wlan0";
        Actor_config offer;
        CHECK(required.matches(offer));
    }

    SUBCASE("Offer missing required bool") {
        Actor_config required;
        required[BK::monitor] = true;
        Actor_config offer;
        CHECK(required.matches(offer));
    }

    SUBCASE("Required nullopt matches anything") {
        Actor_config required;
        Actor_config offer;
        offer[SK::iface] = "wlan0";
        offer[BK::monitor] = true;
        CHECK(required.matches(offer));
    }
}

TEST_CASE("Actor_config - operator+= merge"){
    SUBCASE("Merge non-conflicting configs") {
        Actor_config base;
        base[SK::iface] = "wlan0";
        base[BK::monitor] = true;

        Actor_config other;
        other[SK::driver] = "ath9k";
        other[BK::injection] = true;

        base += other;

        CHECK_EQ(base["iface"], "wlan0");
        CHECK_EQ(base["driver"], "ath9k");
        CHECK(base.get(BK::monitor));
        CHECK(base.get(BK::injection));
    }

    SUBCASE("Merge with same values") {
        Actor_config base;
        base[SK::iface] = "wlan0";

        Actor_config other;
        other[SK::iface] = "wlan0"; // same value

        CHECK_NOTHROW(base += other);
        CHECK_EQ(base[SK::iface].value(), "wlan0");
    }

    SUBCASE("Merge with conflicting values throws") {
        Actor_config base;
        base[SK::iface] = "wlan0";

        Actor_config other;
        other[SK::iface] = "wlan1"; // conflict

        CHECK_THROWS_AS(base += other, runtime_error);
    }
}

TEST_CASE("Actor_config - operator[] accessor"){
    Actor_config actor;
    actor[SK::iface] = "wlan0";

    CHECK(actor["iface"] == "wlan0");

    // Missing key
	CHECK_THROWS_AS(auto a = actor.get(SK::driver), config_err);

    // Key exists but has no value should throw
	 CHECK_THROWS_AS(auto a = actor.get(SK::mac), config_err);
}

TEST_CASE("Actor_config - operator+=complex"){
    json j = {
        {
            "selection", {
                {"driver", "mt76x2u"},
                {"condition", {"STA", "monitor"}}
            }
        }
    };
    Actor_config actor(j);
    Actor_config actor2(j);
    actor[BK::GHz2_4] = false;
    actor[BK::GHz5] = false;
    actor[BK::w80211ac] = false;
    actor[BK::w80211n] = true;
    actor[BK::AP] = false;
    actor[BK::STA] = true;

    CHECK_NOTHROW(actor += actor2);
}