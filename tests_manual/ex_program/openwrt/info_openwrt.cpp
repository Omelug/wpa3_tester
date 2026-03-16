#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include "config/RunStatus.h"
#include "../../manual_test_core/manual_test_wizards.h"
#include "ex_program/external_actors/openwrt/OpenWrtConn.h"
#include "observer/observers.h"
#include "setup/scan.h"
#include "observer/tcpdump_wrapper.h"

using namespace std;
using namespace wpa3_tester;
using namespace filesystem;
using namespace  manual_tests;

static pair<shared_ptr<OpenWrtConn>, ActorPtr>& get_conn_actor() {
    static pair<shared_ptr<OpenWrtConn>, ActorPtr> conn_actor = []() {
        const ActorPtr actor = wb_actor_selection();
        auto conn = make_shared<OpenWrtConn>();
        actor->conn = conn;
        actor->str_con["actor_name"] = "test_actor";
        if (!conn->connect(actor))
            throw manual_test_err("Failed to connect");
        return make_pair(conn, actor);
    }();
    return conn_actor;
}

TEST_CASE("Info OpenWrt"){
    cli_section("Info from OpenWrt actor");
    auto& [conn, actor] = get_conn_actor();

    cli_section("System Information");

    SUBCASE("Hostname") {
        cout << "\n--- Hostname ---" << endl;
        cout << conn->get_hostname();
        CHECK(manual_tests::ask_ok("Valid Hostname?"));
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
}

TEST_CASE("Logger OpenWrt") {
    auto& [conn, actor] = get_conn_actor();

    SUBCASE("Logger") {
        cout << "\n--- Logger Test ---" << endl;

        RunStatus rs;
        rs.actors.emplace(actor["actor_name"], actor);
        const auto test_dir = temp_directory_path() / "openwrt_logger_test";
        create_directories(test_dir);
        rs.process_manager.init_logging(test_dir);

        conn->logger(rs, actor["actor_name"]);
        this_thread::sleep_for(chrono::milliseconds(500));
        conn->exec("logger 'Test log message from wpa3_tester'");
        rs.process_manager.wait_for(actor["actor_name"], "Test log message", chrono::seconds(5));
    }
    cli_section("Test completed successfully");
}

TEST_CASE("Tcpdump OpenWrt") {
    auto& [conn, actor] = get_conn_actor();

    SUBCASE("Tcpdump Remote") {
        cout << "\n--- Tcpdump Remote Test ---" << endl;

        const string chosen_iface = get_openwrt_iface_wizard(conn.get());
        if (chosen_iface.empty()) {
            throw manual_test_err("No interface selected, skipping test.");
        }

        RunStatus rs;

        rs.actors.emplace(actor["actor_name"], actor);
        const auto test_dir = temp_directory_path() / "openwrt_logger_test";
        rs.run_folder = test_dir;
        create_directories(test_dir);
        rs.process_manager.init_logging(path(test_dir / "logger"));

        rs.actors.emplace(actor["actor_name"], actor);
        actor->str_con["iface"] = chosen_iface;

        observer::start_tcpdump_remote(rs, actor["actor_name"], "");
        this_thread::sleep_for(chrono::seconds(1));

        // Check if tcpdump is running on remote
        const string ps_output = conn->exec("ps w | grep tcpdump | grep -v grep");
        CHECK(!ps_output.empty());
        rs.process_manager.stop(actor["actor_name"]+ "_cap");
        const path pcap_path = observer::get_observer_folder(rs, "tcpdump") / (actor["actor_name"] + "_capture.pcap");
        CHECK(exists(pcap_path));
        cout << "Pcap file created: " << pcap_path << endl;
        cout << "Tcpdump remote process running: " << ps_output << endl;
    }
    cli_section("Test completed successfully");
}
