#include <iostream>
#include <string>
#include <memory>
#include "../manual_test_core/manual_test_wizards.h"
#include "attacks/DoS_hard/cookie_guzzler/capture_commit_values.h"
#include "logger/log.h"
#include "logger/error_log.h"
using namespace std;
using namespace wpa3_tester;

void manual_get_commit_values_test() {
    manual_tests::cli_section("SAE Commit Values Capture Test");

    // Get interface selection
    const auto iface_opt = manual_tests::get_iface_wizard();
    const string& iface_name = *iface_opt;
    // Create Actor_config to manage interface
    Actor_config iface_config;
    iface_config.str_con["iface"] = iface_name;
    iface_config.str_con["sniff_iface"] = MONITOR_IFACE_PREFIX + "test";
    iface_config.set_monitor_mode();
    iface_config.create_sniff_iface();

    // Get channel selection
    const int channel = manual_tests::get_2_4_channel_wizard();
    iface_config.set_channel(channel);
    log(LogLevel::INFO, "Interface set to channel " + to_string(channel));

    // Get target selection
    const auto target = manual_tests::get_target_wizard(iface_name, channel);
    const string ssid = target.ssid;
    const string ap_mac_str = target.bssid;

    log(LogLevel::INFO, "Selected target: " + ssid + " (" + ap_mac_str + ")");

    cout << "Enter capture timeout in seconds (default: 30): ";
    string timeout_str;
    getline(cin, timeout_str);
    const int timeout = timeout_str.empty() ? 30 : stoi(timeout_str);

    log(LogLevel::INFO, "Starting SAE commit capture...: ");
    log(LogLevel::INFO, "Interface: " + iface_name);
    log(LogLevel::INFO, "SSID: " + ssid);
    log(LogLevel::INFO, "AP MAC: " + ap_mac_str);
    log(LogLevel::INFO, "Timeout: " + to_string(timeout) + " seconds");

    // Perform the capture
    const HWAddress<6> ap_mac(ap_mac_str);
    RunStatus rs;
    const cookie_guzzler::SAEPair sae_params =
        cookie_guzzler::get_commit_values(rs, iface_name, iface_config["sniff_iface"], ssid, ap_mac, timeout);

    if (sae_params.success) {
        cout << "\n=== CAPTURE SUCCESSFUL ===\n";
        cout << "Scalar (" << sae_params.scalar.size() << " bytes): ";
        for (size_t i = 0; i < sae_params.scalar.size(); ++i) {
            printf("%02x", sae_params.scalar[i]);
            if (i < sae_params.scalar.size() - 1) cout << ":";
        }
        cout << "\n";

        cout << "Element (" << sae_params.element.size() << " bytes): ";
        for (size_t i = 0; i < sae_params.element.size(); ++i) {
            printf("%02x", sae_params.element[i]);
            if (i < sae_params.element.size() - 1) cout << ":";
        }
        cout << "\n";
    } else {
        log(LogLevel::ERROR, "CAPTURE FAILED - No SAE commit values captured within timeout period.");
    }
}

int main() {
    log(LogLevel::INFO,"=== SAE Commit Values Manual Test ===");
    manual_get_commit_values_test();
    return 0;
}
