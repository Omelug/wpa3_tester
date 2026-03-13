#include <iostream>
#include <string>
#include "config/RunStatus.h"
#include "manual_test_core/manual_test_wizards.h"
#include "ex_program/external_actors/openwrt/OpenWrtConn.h"
#include "logger/error_log.h"
#include "setup/scan.h"

using namespace std;
using namespace wpa3_tester;
using namespace filesystem;

int main() {
    manual_tests::cli_section("Info from OpenWrt actor");

    cout << "\nThis test connects to OpenWrt devices defined in connection table" << endl;
    const path conn_table_path =  absolute(path(PROJECT_ROOT_DIR) / "attack_config" /
                                  "example_whitebox_table.csv");

    cout << "Using connection table: " << conn_table_path << endl;

    const vector<ActorPtr> actors = scan::get_actors_conn_table(conn_table_path);
    if (actors.empty()) {cerr << "ERROR: No actors found in connection table" << endl;return 1;}
    cout << "\nFound " << actors.size() << " actor(s) in connection table:" << endl;

    // Display available actors
    for (size_t i = 0; i < actors.size(); ++i) {
        const auto& actor = actors[i];
        cout << "  [" << i << "] ";

        if (actor->str_con["whitebox_host"].has_value()) {
            cout << actor->str_con["whitebox_host"].value();
        } else {
            cout << "Actor_" << i;
        }
        cout << actor->to_str() << endl;
        cout << endl;
    }

    // Select actor
    size_t selected_idx = 0;
    if (actors.size() > 1) {
        cout << "\nSelect actor index [0-" << (actors.size() - 1) << "]: ";
        cin >> selected_idx;

        if (selected_idx >= actors.size()) {
            cerr << "ERROR: Invalid actor index" << endl;
            return 1;
        }
    }

    auto& selected_actor = actors[selected_idx];
    ExternalConn* conn_raw = new OpenWrtConn(selected_actor.get());
    shared_ptr<ExternalConn> conn_ex(conn_raw);
    selected_actor->conn = std::move(conn_ex);

    manual_tests::cli_section("Connecting to " +
        selected_actor->str_con["whitebox_host"].value_or("Unknown"));

    // Create OpenWrt connection
    const auto conn = dynamic_cast<OpenWrtConn*>(selected_actor.get()->conn.get());
    if (!conn) throw runtime_error("Connection is not OpenWrtConn");

    cout << "Establishing SSH connection..." << endl;
    if (!conn->connect()) {
        cerr << "ERROR: Failed to connect" << endl;
        return 1;
    }

    // Get and display system information
    manual_tests::cli_section("System Information");

    try {
        cout << "\n--- Hostname ---" << endl;
        cout << conn->get_hostname();
        cout << "\n--- OpenWrt Release ---" << endl;
        cout << conn->exec("cat /etc/openwrt_release");
        cout << "\n--- Kernel Version ---" << endl;
        cout << conn->exec("uname -r");
        cout << "\n--- Memory Info ---" << endl;
        cout << conn->exec("free -h");
        cout << "\n--- CPU Info ---" << endl;
        string cpuinfo = conn->exec("cat /proc/cpuinfo | grep -E '(model name|Processor|Hardware)'");
        if (cpuinfo.empty()) {cpuinfo = conn->exec("cat /proc/cpuinfo | head -n 10");}
        cout << cpuinfo;
        cout << "\n--- Network Interfaces ---" << endl;
        cout << conn->get_interfaces();
        cout << "\n--- WiFi Status ---" << endl;
        try {
            cout << conn->get_wifi_status();
        } catch (...) {
            cout << "(iwinfo not available or no WiFi interfaces)" << endl;
        }

        // Hostapd version (if available)
        cout << "\n--- Hostapd Version ---" << endl;
        try {
            const string hostapd_version = conn->exec("hostapd -v 2>&1 | head -n 1");
            cout << hostapd_version;
            if (hostapd_version.back() != '\n') cout << endl;
        } catch (...) {
            cout << "(hostapd not installed)" << endl;
        }

        // UCI wireless config
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

    } catch (const ex_conn_err& e) {
        cerr << "\nERROR during command execution: " << e.what() << endl;
        return 1;
    } catch (const exception& e) {
        cerr << "\nERROR: " << e.what() << endl;
        return 1;
    }

    manual_tests::cli_section("Test completed successfully");

    return 0;
}

