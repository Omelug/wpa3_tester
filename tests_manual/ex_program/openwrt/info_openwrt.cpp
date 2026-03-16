#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <iostream>
#include <string>
#include "config/RunStatus.h"
#include "../../manual_test_core/manual_test_wizards.h"
#include "ex_program/external_actors/openwrt/OpenWrtConn.h"
#include "setup/scan.h"

using namespace std;
using namespace wpa3_tester;
using namespace filesystem;
using namespace  manual_tests;

TEST_CASE("Info OpenWrt") {
    cli_section("Info from OpenWrt actor");

    static pair<shared_ptr<OpenWrtConn>, ActorPtr> conn_actor = []() {
        const ActorPtr actor = wb_actor_selection();
        auto conn_raw = new OpenWrtConn();
        const shared_ptr<OpenWrtConn> c(conn_raw);
        actor->conn = c;
        REQUIRE(c->connect(actor));
        return make_pair(c, actor);
    }();

    auto conn = conn_actor.first;
    auto actor = conn_actor.second;

    cli_section("System Information");

    SUBCASE("Hostname") {
        cout << "\n--- Hostname ---" << endl;
        cout << conn->get_hostname();
        CHECK(ask_ok("Valid Hostname?"));
    }

    SUBCASE("Hostapd Version") {
        cout << "\n--- Hostapd Version ---" << endl;
        const string hostapd_version = conn->exec("hostapd -v 2>&1 | head -n 1");
        cout << hostapd_version << endl;
        CHECK(ask_ok("Valid Hostapd Version?"));
    }

    SUBCASE("UCI Wireless Config") {
        cout << "\n--- UCI Wireless Config ---" << endl;
        try {
            const string uci_wireless = conn->exec("uci show wireless 2>/dev/null");
            if (!uci_wireless.empty()) {
                cout << uci_wireless;
            } else {
                cout << "(no wireless configuration)" << endl;
            }
        } catch (...) {
            cout << "(failed to read wireless config)" << endl;
        }
        CHECK(ask_ok("Valid UCI Wireless Config?"));
    }

    SUBCASE("Time Fix") {
        cout << "\n--- Time Fix Test ---" << endl;

        long expected = stol(conn->exec("date +%s"));
        cout << "Expected time: " << expected << " (" << conn->exec("date") << ")" << endl;

        // Mess up the time
        conn->exec("date -s '2020-01-01 00:00:00'");
        long wrong = stol(conn->exec("date +%s"));
        cout << "Wrong time: " << wrong << " (" << conn->exec("date") << ")" << endl;

        // time is wrong
        CHECK((abs(wrong - expected) > 3600 * 24 * 365)); // More than a year off

        // Call time_fix, expect success
        CHECK_NOTHROW(conn->time_fix());

        long fixed = stol(conn->exec("date +%s"));
        cout << "Fixed time: " << fixed << " (" << conn->exec("date") << ")" << endl;
        CHECK((abs(fixed - expected) < 60));
    }

    cli_section("Test completed successfully");
}