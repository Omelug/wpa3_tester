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

// --- Actor_config::to_str

TEST_CASE("Actor_config::to_str - empty config"){
    Actor_config actor;
    CHECK(actor.to_str().empty());
}

TEST_CASE("Actor_config::to_str - string keys only"){
    Actor_config actor;
    actor[SK::iface]  = "wlan0";
    actor[SK::driver] = "ath9k";

    const auto s = actor.to_str();
    CHECK_NE(s.find("iface=wlan0"), string::npos);
    CHECK_NE(s.find("driver=ath9k"), string::npos);
    // no bracket section when no bool keys set
    CHECK_EQ(s.find('['), string::npos);
}

TEST_CASE("Actor_config::to_str - bool keys true and false"){
    Actor_config actor;
    actor[BK::AP]        = true;
    actor[BK::injection] = false;

    const auto s = actor.to_str();
    CHECK_NE(s.find("["), string::npos);
    CHECK_NE(s.find("AP"), string::npos);
    CHECK_NE(s.find("!injection"), string::npos);
}

TEST_CASE("Actor_config::to_str - mixed string and bool keys"){
    Actor_config actor;
    actor[SK::iface] = "wlan1";
    actor[BK::monitor] = true;

    const auto s = actor.to_str();
    CHECK_NE(s.find("iface=wlan1"), string::npos);
    CHECK_NE(s.find("monitor"), string::npos);
}

// to_json
TEST_CASE("Actor_config::to_json - empty config"){
    Actor_config actor;
    const auto j = actor.to_json();

    REQUIRE(j.contains("selection"));
    CHECK(j["selection"].empty());
    CHECK_FALSE(j.contains("netns"));
    CHECK_FALSE(j.contains("source"));
}

TEST_CASE("Actor_config::to_json - string keys in selection"){
    Actor_config actor;
    actor[SK::iface]  = "wlan0";
    actor[SK::driver] = "ath9k";

    const auto j = actor.to_json();
    REQUIRE(j.contains("selection"));
    CHECK_EQ(j["selection"]["iface"],  "wlan0");
    CHECK_EQ(j["selection"]["driver"], "ath9k");
}

TEST_CASE("Actor_config::to_json - bool conditions"){
    Actor_config actor;
    actor[BK::monitor]   = true;
    actor[BK::injection] = false;

    const auto j = actor.to_json();
    REQUIRE(j["selection"].contains("condition"));
    const auto &cond = j["selection"]["condition"];
    CHECK_NE(cond.end(), std::find(cond.begin(), cond.end(), "monitor"));
    CHECK_NE(cond.end(), std::find(cond.begin(), cond.end(), "!injection"));
}

TEST_CASE("Actor_config::to_json - netns and source are top-level, not in selection"){
    Actor_config actor;
    actor[SK::netns]  = "sta_ns";
    actor[SK::source] = "hardware";

    const auto j = actor.to_json();
    CHECK_EQ(j["netns"],  "sta_ns");
    CHECK_EQ(j["source"], "hardware");
    CHECK_FALSE(j["selection"].contains("netns"));
    CHECK_FALSE(j["selection"].contains("source"));
}

TEST_CASE("Actor_config::to_json - round-trip via json constructor"){
    Actor_config orig;
    orig[SK::iface]    = "wlan0";
    orig[SK::driver]   = "ath9k";
    orig[SK::netns]    = "sta";
    orig[BK::monitor]  = true;
    orig[BK::AP]       = false;

    Actor_config restored(orig.to_json());

    CHECK_EQ(restored[SK::iface].value(),  "wlan0");
    CHECK_EQ(restored[SK::driver].value(), "ath9k");
    CHECK_EQ(restored[SK::netns].value(),  "sta");
    CHECK(restored[BK::monitor].value());
    CHECK_FALSE(restored[BK::AP].value());
}

// ActorPtr

TEST_CASE("ActorPtr - basic accessors"){
    auto cfg = make_shared<Actor_config>();
    (*cfg)[SK::iface]   = "wlan2";
    (*cfg)[BK::monitor] = true;

    ActorPtr ap(cfg);

    SUBCASE("operator->"){
        CHECK_EQ(ap->operator[](SK::iface).value(), "wlan2");
    }

    SUBCASE("operator*"){
        CHECK_EQ((*ap)[SK::iface].value(), "wlan2");
    }

    SUBCASE("get()"){
        CHECK_EQ(ap.get(), cfg.get());
    }

    SUBCASE("shared()"){
        CHECK(ap.shared() == cfg);
    }

    SUBCASE("operator[](string)"){
        CHECK_EQ(ap["iface"], "wlan2");
    }

    SUBCASE("operator[](SK) const"){
        const ActorPtr cap(cfg);
        CHECK_EQ(cap[SK::iface].value(), "wlan2");
    }

    SUBCASE("operator[](BK) mutable"){
        ap[BK::injection] = true;
        CHECK(ap[BK::injection].value());
    }

    SUBCASE("operator[](BK) const"){
        const ActorPtr cap(cfg);
        CHECK(cap[BK::monitor].value());
    }
}

TEST_CASE("ActorPtr - equality and ordering"){
    auto cfg1 = make_shared<Actor_config>();
    auto cfg2 = make_shared<Actor_config>();

    ActorPtr a(cfg1), b(cfg1), c(cfg2);

    CHECK_EQ(a, b);
    CHECK_NE(a, c);
    // strict weak ordering: exactly one of a<c or c<a must hold
    CHECK_NE((a < c),(c < a));
}