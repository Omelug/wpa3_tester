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
    CHECK(actor[SK::driver_name].has_value());
    CHECK_EQ(actor[SK::driver_name].value(), "ath9k");
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
        required.set(SK::iface, "wlan0");
        required.set(BK::monitor, true);

        Actor_config offer;
        offer.set(SK::iface, "wlan0");
        offer.set(SK::driver_name, "ath9k");
        offer.set(BK::monitor, true);
        offer.set(BK::injection, true);

        CHECK(required.matches(offer));
    }

    SUBCASE("String mismatch") {
        Actor_config required;
        required.set(SK::iface, "wlan0");

        Actor_config offer;
        offer.set(SK::iface, "wlan1");

        CHECK_FALSE(required.matches(offer));
    }

    SUBCASE("Bool condition mismatch") {
        Actor_config required;
        required.set(BK::monitor, true);

        Actor_config offer;
        offer.set(BK::monitor, false);

        CHECK_FALSE(required.matches(offer));
    }

    SUBCASE("Offer missing required string") {
        Actor_config required;
        required.set(SK::iface, "wlan0");
        Actor_config offer;
        CHECK(required.matches(offer));
    }

    SUBCASE("Offer missing required bool") {
        Actor_config required;
        required.set(BK::monitor, true);
        Actor_config offer;
        CHECK(required.matches(offer));
    }

    SUBCASE("Required nullopt matches anything") {
        Actor_config required;
        Actor_config offer;
        offer.set(SK::iface, "wlan0");
        offer.set(BK::monitor, true);
        CHECK(required.matches(offer));
    }
}

TEST_CASE("Actor_config - operator+= merge"){
    SUBCASE("Merge non-conflicting configs") {
        Actor_config base;
        base.set(SK::iface, "wlan0");
        base.set(BK::monitor, true);

        Actor_config other;
        other.set(SK::driver_name, "ath9k");
        other.set(BK::injection, true);

        base += other;

        CHECK_EQ(base["iface"], "wlan0");
        CHECK_EQ(base["driver"], "ath9k");
        CHECK(base.get(BK::monitor));
        CHECK(base.get(BK::injection));
    }

    SUBCASE("Merge with same values") {
        Actor_config base;
        base.set(SK::iface, "wlan0");

        Actor_config other;
        other.set(SK::iface, "wlan0"); // same value

        CHECK_NOTHROW(base += other);
        CHECK_EQ(base[SK::iface].value(), "wlan0");
    }

    SUBCASE("Merge with conflicting values throws") {
        Actor_config base;
        base.set(SK::iface, "wlan0");

        Actor_config other;
        other.set(SK::iface, "wlan1"); // conflict

        CHECK_THROWS_AS(base += other, run_err);
    }
}

TEST_CASE("Actor_config - operator[] accessor"){
    Actor_config actor;
    actor.set(SK::iface, "wlan0");

    CHECK(actor["iface"] == "wlan0");

    // Missing key
	CHECK_THROWS_AS(auto a = actor.get(SK::driver_name), config_err);

    // Key exists but has no value should throw
	 CHECK_THROWS_AS(auto a = actor.get(SK::mac), config_err);

    // permanent_mac missing should throw
	 CHECK_THROWS_AS(auto a = actor.get(SK::permanent_mac), config_err);
}

TEST_CASE("Actor_config - permanent_mac normalization"){
    Actor_config actor;
    actor.set(SK::permanent_mac, "AA:BB:CC:DD:EE:FF");
    CHECK_EQ(actor.get(SK::permanent_mac), "aa:bb:cc:dd:ee:ff");
}

TEST_CASE("Actor_config - permanent_mac from JSON selection"){
    json j = {
        {
            "selection", {
                {"iface", "wlan0"},
                {"permanent_mac", "11:22:33:44:55:66"}
            }
        }
    };

    Actor_config actor(j);
	CHECK(actor[SK::permanent_mac].has_value());
    CHECK_EQ(actor.get(SK::permanent_mac), "11:22:33:44:55:66");
}

TEST_CASE("Actor_config - get_channel"){
    SUBCASE("Missing channel throws") {
        Actor_config actor;
        CHECK_THROWS_AS(actor.get_channel(), config_err);
    }

    SUBCASE("Multiple bands throw (2_4GHz + 6GHz)") {
        Actor_config actor;
        actor.set(SK::channel, "6");
        actor[BK::GHz2_4] = true;
        actor[BK::GHz6] = true;
        CHECK_THROWS_AS(actor.get_channel(), config_err);
    }

    SUBCASE("Multiple bands throw (5GHz + 6GHz)") {
        Actor_config actor;
        actor.set(SK::channel, "36");
        actor[BK::GHz5] = true;
        actor[BK::GHz6] = true;
        CHECK_THROWS_AS(actor.get_channel(), config_err);
    }

    SUBCASE("Valid 2.4GHz channel with explicit band") {
        Actor_config actor;
        actor.set(SK::channel, "6");
        actor[BK::GHz2_4] = true;
        auto [ch_num, band] = actor.get_channel();
        CHECK_EQ(ch_num, 6);
        CHECK_EQ(band, WifiBand::BAND_2_4);
    }

    SUBCASE("Valid 5GHz channel with explicit band") {
        Actor_config actor;
        actor.set(SK::channel, "36");
        actor[BK::GHz5] = true;
        auto ch = actor.get_channel();
        CHECK_EQ(ch.ch_num, 36);
        CHECK_EQ(ch.band, WifiBand::BAND_5);
    }

    SUBCASE("Valid 6GHz channel with explicit band") {
        Actor_config actor;
        actor.set(SK::channel, "1");
        actor[BK::GHz6] = true;
        auto [ch_num, band] = actor.get_channel();
        CHECK_EQ(ch_num, 1);
        CHECK_EQ(band, WifiBand::BAND_6);
    }

    SUBCASE("Inferred 2.4GHz from channel number") {
        Actor_config actor;
        actor.set(SK::channel, "11");
        auto [ch_num, band] = actor.get_channel();
        CHECK_EQ(ch_num, 11);
        CHECK_EQ(band, WifiBand::BAND_2_4);
    }

    SUBCASE("Inferred 5GHz from channel number") {
        Actor_config actor;
        actor.set(SK::channel, "100");
        auto [ch_num, band] = actor.get_channel();
        CHECK_EQ(ch_num, 100);
        CHECK_EQ(band, WifiBand::BAND_5);
    }

    SUBCASE("Invalid channel throws") {
        Actor_config actor;
        actor.set(SK::channel, "999");
        CHECK_THROWS_AS(actor.get_channel(), config_err);
    }
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
    actor.set(BK::AP, false);
    actor.set(BK::STA, true);

    CHECK_NOTHROW(actor += actor2);
}

// --- Actor_config::to_str

TEST_CASE("Actor_config::to_str - empty config"){
    Actor_config actor;
    CHECK(actor.to_str().empty());
}

TEST_CASE("Actor_config::to_str - string keys only"){
    Actor_config actor;
    actor.set(SK::iface, "wlan0");
    actor.set(SK::driver_name, "ath9k");

    const auto s = actor.to_str();
    CHECK_NE(s.find("iface=wlan0"), string::npos);
    CHECK_NE(s.find("driver=ath9k"), string::npos);
    // no bracket section when no bool keys set
    CHECK_EQ(s.find('['), string::npos);
}

TEST_CASE("Actor_config::to_str - bool keys true and false"){
    Actor_config actor;
    actor.set(BK::AP, true);
    actor.set(BK::injection, false);

    const auto s = actor.to_str();
    CHECK_NE(s.find("["), string::npos);
    CHECK_NE(s.find("AP"), string::npos);
    CHECK_NE(s.find("!injection"), string::npos);
}

TEST_CASE("Actor_config::to_str - mixed string and bool keys"){
    Actor_config actor;
    actor.set(SK::iface, "wlan1");
    actor.set(BK::monitor, true);

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
    actor.set(SK::iface, "wlan0");
    actor.set(SK::driver_name, "ath9k");

    const auto j = actor.to_json();
    REQUIRE(j.contains("selection"));
    CHECK_EQ(j["selection"]["iface"],  "wlan0");
    CHECK_EQ(j["selection"]["driver"], "ath9k");
}

TEST_CASE("Actor_config::to_json - bool conditions"){
    Actor_config actor;
    actor.set(BK::monitor, true);
    actor.set(BK::injection, false);

    const auto j = actor.to_json();
    REQUIRE(j["selection"].contains("condition"));
    const auto &cond = j["selection"]["condition"];
    CHECK_NE(cond.end(), ranges::find(cond, "monitor"));
    CHECK_NE(cond.end(), ranges::find(cond, "!injection"));
}

TEST_CASE("Actor_config::to_json - netns and source are top-level, not in selection"){
    Actor_config actor;
    actor.set(SK::netns, "sta_ns");
    actor.set(SK::source, "hardware");

    const auto j = actor.to_json();
    CHECK_EQ(j["netns"],  "sta_ns");
    CHECK_EQ(j["source"], "hardware");
    CHECK_FALSE(j["selection"].contains("netns"));
    CHECK_FALSE(j["selection"].contains("source"));
}

TEST_CASE("Actor_config::to_json - round-trip via json constructor"){
    Actor_config orig;
    orig.set(SK::iface, "wlan0");
    orig.set(SK::driver_name, "ath9k");
    orig.set(SK::netns, "sta");
    orig.set(BK::monitor, true);
    orig.set(BK::AP, false);

    Actor_config restored(orig.to_json());

    CHECK_EQ(restored[SK::iface].value(),  "wlan0");
    CHECK_EQ(restored[SK::driver_name].value(), "ath9k");
    CHECK_EQ(restored[SK::netns].value(),  "sta");
    CHECK(restored[BK::monitor].value());
    CHECK_FALSE(restored[BK::AP].value());
}

// ActorPtr

TEST_CASE("ActorPtr - basic accessors"){
    auto cfg = ActorPtr(make_shared<Actor_config>());
    cfg->set(SK::iface, "wlan2");
    cfg->set(BK::monitor, true);

    ActorPtr ap(cfg);

    SUBCASE("operator->"){
        CHECK_EQ(ap->get(SK::iface), "wlan2");
    }

    SUBCASE("operator*"){
        CHECK_EQ(ap->get(SK::iface), "wlan2");
    }

    SUBCASE("get()"){
        CHECK_EQ(ap.get(), cfg.get());
    }

    SUBCASE("shared()"){
        CHECK(ap.shared() == cfg.shared());
    }

    SUBCASE("operator[](string)"){
        CHECK_EQ(ap["iface"], "wlan2");
    }

    SUBCASE("operator[](SK) const"){
        const ActorPtr cap(cfg);
        CHECK_EQ(cap[SK::iface].value(), "wlan2");
    }

    SUBCASE("operator[](BK) mutable"){
        ap->set(BK::injection, true);
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
	CHECK_NE(a < c, c < a);
}

// -----------------
// to_str / to_json with ParamFilter via ActorPtr

TEST_CASE("ActorPtr::to_str - filter restricts SK output"){
    ActorPtr ap(make_shared<Actor_config>());
    ap->set(SK::iface,       "wlan0");
    ap->set(SK::driver_name, "ath9k");
    ap->set(SK::ssid,        "MyNet");

    ParamFilter filter{{SK::iface}, {}};
    const auto s = ap->to_str(&filter);

    CHECK_NE(s.find("iface=wlan0"),  string::npos);
    CHECK_EQ(s.find("driver=ath9k"), string::npos);
    CHECK_EQ(s.find("ssid=MyNet"),   string::npos);
}

TEST_CASE("ActorPtr::to_str - filter restricts BK output"){
    ActorPtr ap(make_shared<Actor_config>());
    ap->set(BK::monitor,   true);
    ap->set(BK::AP,        false);
    ap->set(BK::injection, true);

    ParamFilter filter{{}, {BK::monitor}};
    const auto s = ap->to_str(&filter);

    CHECK_NE(s.find("monitor"),   string::npos);
    CHECK_EQ(s.find("AP"),        string::npos);
    CHECK_EQ(s.find("injection"), string::npos);
}

TEST_CASE("ActorPtr::to_str - filter with mixed SK and BK"){
    ActorPtr ap(make_shared<Actor_config>());
    ap->set(SK::iface,       "wlan1");
    ap->set(SK::driver_name, "mt76");
    ap->set(BK::AP,          true);
    ap->set(BK::monitor,     false);

    ParamFilter filter{{SK::iface}, {BK::AP}};
    const auto s = ap->to_str(&filter);

    CHECK_NE(s.find("iface=wlan1"), string::npos);
    CHECK_EQ(s.find("driver=mt76"), string::npos);
    CHECK_NE(s.find("AP"),          string::npos);
    CHECK_EQ(s.find("monitor"),     string::npos);
}

TEST_CASE("ActorPtr::to_str - empty filter produces empty string"){
    ActorPtr ap(make_shared<Actor_config>());
    ap->set(SK::iface, "wlan0");
    ap->set(BK::monitor, true);

    ParamFilter filter{{}, {}};
    CHECK(ap->to_str(&filter).empty());
}

TEST_CASE("ActorPtr::to_json - filter restricts SK fields in selection"){
    ActorPtr ap(make_shared<Actor_config>());
    ap->set(SK::iface,       "wlan0");
    ap->set(SK::driver_name, "ath9k");
    ap->set(SK::ssid,        "MyNet");

    ParamFilter filter{{SK::iface}, {}};
    const auto j = ap->to_json(&filter);

    REQUIRE(j.contains("selection"));
    CHECK(j["selection"].contains("iface"));
    CHECK_FALSE(j["selection"].contains("driver"));
    CHECK_FALSE(j["selection"].contains("ssid"));
    CHECK_FALSE(j["selection"].contains("condition"));
}

TEST_CASE("ActorPtr::to_json - filter restricts BK conditions"){
    ActorPtr ap(make_shared<Actor_config>());
    ap->set(BK::monitor,   true);
    ap->set(BK::injection, false);
    ap->set(BK::AP,        true);

    ParamFilter filter{{}, {BK::monitor}};
    const auto j = ap->to_json(&filter);

    REQUIRE(j["selection"].contains("condition"));
    const auto &cond = j["selection"]["condition"];
    CHECK_NE(cond.end(), ranges::find(cond, "monitor"));
    CHECK_EQ(cond.end(), ranges::find(cond, "!injection"));
    CHECK_EQ(cond.end(), ranges::find(cond, "AP"));
}

TEST_CASE("ActorPtr::to_json - filter with mixed SK and BK"){
    ActorPtr ap(make_shared<Actor_config>());
    ap->set(SK::iface,       "wlan1");
    ap->set(SK::driver_name, "mt76");
    ap->set(BK::AP,          true);
    ap->set(BK::monitor,     false);

    ParamFilter filter{{SK::iface}, {BK::AP}};
    const auto j = ap->to_json(&filter);

    REQUIRE(j.contains("selection"));
    CHECK(j["selection"].contains("iface"));
    CHECK_FALSE(j["selection"].contains("driver"));
    REQUIRE(j["selection"].contains("condition"));
    const auto &cond = j["selection"]["condition"];
    CHECK_NE(cond.end(), ranges::find(cond, "AP"));
    CHECK_EQ(cond.end(), ranges::find(cond, "!monitor"));
}

TEST_CASE("ActorPtr::to_json - filter suppresses netns/source top-level keys"){
    ActorPtr ap(make_shared<Actor_config>());
    ap->set(SK::iface, "wlan0");
    ap->set(SK::netns, "sta_ns");

    ParamFilter filter{{SK::iface}, {}};
    const auto j = ap->to_json(&filter);

    CHECK_FALSE(j.contains("netns"));
    CHECK_FALSE(j.contains("source"));
}

TEST_CASE("ActorPtr::to_json - empty filter produces empty selection"){
    ActorPtr ap(make_shared<Actor_config>());
    ap->set(SK::iface, "wlan0");
    ap->set(BK::monitor, true);

    ParamFilter filter{{}, {}};
    const auto j = ap->to_json(&filter);

    REQUIRE(j.contains("selection"));
    CHECK(j["selection"].empty());
}