#include <iostream>
#include <string>
#include <memory>
#include "../manual_test_core/manual_test_wizards.h"
#include "attacks/DoS_hard/cookie_guzzler/capture_commit_values.h"
#include "logger/log.h"
#include "logger/error_log.h"

using namespace std;
using namespace wpa3_tester;
using namespace Tins;

void manual_get_commit_values_test(){
    manual_tests::cli_section("SAE Commit Values Capture Test");

    // Get interface selection
    const auto iface_opt = manual_tests::get_iface_wizard();
    const string &iface_name = *iface_opt;
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
    const optional<dos_helpers::SAEPair> sae_params =
            cookie_guzzler::get_commit_values(rs, iface_name, iface_config["sniff_iface"], ssid, ap_mac, timeout);

    if(sae_params.has_value()){
        cout << "\n=== CAPTURE SUCCESSFUL ===\n";
        cout << sae_params->to_str() << flush;
    } else{
        log(LogLevel::ERROR, "CAPTURE FAILED - No SAE commit values captured within timeout period.");
    }
}

int main(){
    log(LogLevel::INFO, "=== SAE Commit Values Manual Test ===");
    manual_get_commit_values_test();
    return 0;
}
