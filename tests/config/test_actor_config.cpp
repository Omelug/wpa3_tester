#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <nlohmann/json.hpp>
#include "config/Actor_config.h"
#include "logger/error_log.h"

using namespace std;
using namespace wpa3_tester;
using json = nlohmann::json;

TEST_CASE("Actor_config - json constructor with selection") {
    json j = {
        {
            "selection", {
                {"iface", "wlan0"},
                {"driver", "ath9k"},
                {"condition", {"monitor", "injection"}}
            }
        },
        {"netns", "sta"},
        {"type", "STA"}
    };

    Actor_config actor(j);

    CHECK(actor.str_con.at("iface").has_value());
    CHECK((actor.str_con.at("iface").value() == "wlan0"));
    CHECK(actor.str_con.at("driver").has_value());
    CHECK((actor.str_con.at("driver").value() == "ath9k"));
    CHECK((actor.str_con.at("netns").value() == "sta"));

    CHECK((actor.bool_conditions.at("monitor").value_or(false) == true));
    CHECK((actor.bool_conditions.at("injection").value_or(false) == true));
    CHECK_FALSE((actor.bool_conditions.at("AP").has_value()));
}

TEST_CASE("Actor_config - json constructor without selection") {
    json j = {{"type", "STA"}};

    Actor_config actor(j);

    // Should remain empty/nullopt
    CHECK_FALSE(actor.str_con.at("iface").has_value());
    CHECK_FALSE(actor.bool_conditions.at("monitor").has_value());
}

TEST_CASE("Actor_config - matches method") {
    SUBCASE("Exact match") {
        Actor_config required;
        required.str_con["iface"] = "wlan0";
        required.bool_conditions["monitor"] = true;

        Actor_config offer;
        offer.str_con["iface"] = "wlan0";
        offer.str_con["driver"] = "ath9k"; // extra fields ok
        offer.bool_conditions["monitor"] = true;
        offer.bool_conditions["injection"] = true; // extra fields ok

        CHECK(required.matches(offer));
    }

    SUBCASE("String mismatch") {
        Actor_config required;
        required.str_con["iface"] = "wlan0";

        Actor_config offer;
        offer.str_con["iface"] = "wlan1";

        CHECK_FALSE(required.matches(offer));
    }

    SUBCASE("Bool condition mismatch") {
        Actor_config required;
        required.bool_conditions["monitor"] = true;

        Actor_config offer;
        offer.bool_conditions["monitor"] = false;

        CHECK_FALSE(required.matches(offer));
    }

    SUBCASE("Offer missing required string") {
        Actor_config required;
        required.str_con["iface"] = "wlan0";
        Actor_config offer;
        CHECK(required.matches(offer));
    }

    SUBCASE("Offer missing required bool") {
        Actor_config required;
        required.bool_conditions["monitor"] = true;
        Actor_config offer;
        CHECK(required.matches(offer));
    }

    SUBCASE("Required nullopt matches anything") {
        Actor_config required;
        Actor_config offer;
        offer.str_con["iface"] = "wlan0";
        offer.bool_conditions["monitor"] = true;
        CHECK(required.matches(offer));
    }
}

TEST_CASE("Actor_config - operator+= merge") {
    SUBCASE("Merge non-conflicting configs") {
        Actor_config base;
        base.str_con["iface"] = "wlan0";
        base.bool_conditions["monitor"] = true;

        Actor_config other;
        other.str_con["driver"] = "ath9k";
        other.bool_conditions["injection"] = true;

        base += other;

        CHECK((base["iface"] == "wlan0"));
        CHECK((base["driver"] == "ath9k"));
        CHECK((base.get_bool("monitor") == true));
        CHECK((base.get_bool("injection") == true));
    }

    SUBCASE("Merge with same values") {
        Actor_config base;
        base.str_con["iface"] = "wlan0";

        Actor_config other;
        other.str_con["iface"] = "wlan0"; // same value

        CHECK_NOTHROW(base += other);
        CHECK((base.str_con.at("iface").value() == "wlan0"));
    }

    SUBCASE("Merge with conflicting values throws") {
        Actor_config base;
        base.str_con["iface"] = "wlan0";

        Actor_config other;
        other.str_con["iface"] = "wlan1"; // conflict!

        CHECK_THROWS_AS(base += other, runtime_error);
    }
}

TEST_CASE("Actor_config - operator[] accessor") {
    Actor_config actor;
    actor.str_con["iface"] = "wlan0";

    CHECK(actor["iface"] == "wlan0");

    // Missing key should throw
    CHECK_THROWS_AS(actor["driver"], config_error);

    // Key exists but has no value should throw
    CHECK_THROWS_AS(actor["mac"], config_error);
}

TEST_CASE("Actor_config - operator+=complex") {
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
    actor.bool_conditions["2_4GHz"] = false;
    actor.bool_conditions["5GHz"] = false;
    actor.bool_conditions["80211ac"] = false;
    actor.bool_conditions["80211n"] = true;
    actor.bool_conditions["AP"] = false;
    actor.bool_conditions["STA"] = true;

    CHECK_NOTHROW(actor += actor2);
}