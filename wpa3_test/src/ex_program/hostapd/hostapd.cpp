#include "ex_program/hostapd/hostpad.h"
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include "logger/log.h"

using namespace std;
void hostapd_config(const string& run_folder, const nlohmann::json& ap_setup) {
    namespace fs = filesystem;

    fs::path folder(run_folder);
    fs::path cfg_path = folder / "hostapd.conf";

    error_code ec;
    fs::create_directories(folder, ec);
    if (ec) {
        log(LogLevel::ERROR, "hostapd_config: failed to ensure run folder: {}: {}",folder.string(),ec.message());
        throw runtime_error("hostapd_config: unable to create run folder");
    }

    ofstream out(cfg_path);
    if (!out) {
        log(LogLevel::ERROR, "hostapd_config: failed to open config file: {}", cfg_path.string());
        throw runtime_error("hostapd_config: unable to open config file");
    }
    // Minimal hostapd.conf based on provided JSON; use defaults if keys are missing
    const auto iface        = ap_setup.value("interface", string{"wlan0"});
    const auto ssid         = ap_setup.value("ssid",      string{"wpa3_test"});
    const auto channel      = ap_setup.value("channel",   6);
    const auto hw_mode      = ap_setup.value("hw_mode",   string{"g"});
    const auto wpa          = ap_setup.value("wpa",       2); // WPA2/WPA3 mixed
    const auto wpa_key_mgmt = ap_setup.value("wpa_key_mgmt", string{"SAE"});
    const auto rsn_pairwise = ap_setup.value("rsn_pairwise", string{"CCMP"});
    const auto passphrase   = ap_setup.value("wpa_passphrase", string{"password123"});

    out << "interface=" << iface << '\n'
        << "driver=nl80211" << '\n'
        << "ssid=" << ssid << '\n'
        << "channel=" << channel << '\n'
        << "hw_mode=" << hw_mode << '\n'
        << "wpa=" << wpa << '\n'
        << "wpa_key_mgmt=" << wpa_key_mgmt << '\n'
        << "rsn_pairwise=" << rsn_pairwise << '\n'
        << "wpa_passphrase=" << passphrase << '\n';

    out.close();

    log(LogLevel::INFO, "hostapd_config: written {}", cfg_path.string());
}
void wpa_supplicant_config(const string& run_folder, const nlohmann::json& client_setup) {
    namespace fs = filesystem;

    fs::path folder(run_folder);
    fs::path cfg_path = folder / "wpa_supplicant.conf";

    error_code ec;
    fs::create_directories(folder, ec);
    if (ec) {
        log(LogLevel::ERROR, "wpa_supplicant_config: failed to ensure run folder: {}: {}", folder.string(), ec.message());
        throw runtime_error("wpa_supplicant_config: unable to create run folder");
    }

    ofstream out(cfg_path);
    if (!out) {
        log(LogLevel::ERROR, "wpa_supplicant_config: failed to open config file: {}", cfg_path.string());
        throw runtime_error("wpa_supplicant_config: unable to open config file");
    }

    // Minimal wpa_supplicant.conf based on provided JSON; use defaults if keys are missing
    const auto iface      = client_setup.value("interface", string{"wlan1"});
    const auto ssid       = client_setup.value("ssid",      string{"wpa3_test"});
    const auto passphrase = client_setup.value("psk",       string{"password123"});

    out << "ctrl_interface=/var/run/wpa_supplicant" << '\n'
        << "ap_scan=1" << '\n'
        << "network={" << '\n'
        << "    ssid=\"" << ssid << "\"" << '\n'
        << "    psk=\"" << passphrase << "\"" << '\n'
        << "}" << '\n';

    out.close();

    log(LogLevel::INFO, "wpa_supplicant_config: written {}", cfg_path.string());
}

