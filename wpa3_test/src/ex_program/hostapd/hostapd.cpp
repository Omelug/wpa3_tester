#include "ex_program/hostapd/hostpad.h"
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include "logger/log.h"

using namespace std;
string hostapd_config(const string& run_folder, const nlohmann::json& ap_setup) {
    namespace fs = filesystem;

    fs::path folder(run_folder);
    fs::path cfg_path = folder / "hostapd.conf";

    error_code ec;
    fs::create_directories(folder, ec);
    if (ec) {
        log(LogLevel::ERROR,
            ("hostapd_config: failed to ensure run folder: " + folder.string() + ": " + ec.message()).c_str());
        throw runtime_error("hostapd_config: unable to create run folder");
    }

    ofstream out(cfg_path);
    if (!out) {
        log(LogLevel::ERROR, ("hostapd_config: failed to open config file: " + cfg_path.string()).c_str());
        throw runtime_error("hostapd_config: unable to open config file");
    }
    // write config
    for (auto it = ap_setup.begin(); it != ap_setup.end(); ++it) {
        out << it.key() << "=";
        if (it.value().is_string()) {
            out << it.value().get<string>();
        } else {
            out << it.value().dump();
        }
        out << "\n";
    }

    out.close();
    log(LogLevel::INFO, ("hostapd_config: written " + cfg_path.string()).c_str());
    return cfg_path.string();
}
string wpa_supplicant_config(const string& run_folder, const nlohmann::json& client_setup) {
    namespace fs = filesystem;

    fs::path folder(run_folder);
    fs::path cfg_path = folder / "wpa_supplicant.conf";

    error_code ec;
    fs::create_directories(folder, ec);
    if (ec) {
        log(LogLevel::ERROR,
            ("wpa_supplicant_config: failed to ensure run folder: " + folder.string() + ": " + ec.message()).c_str());
        throw runtime_error("wpa_supplicant_config: unable to create run folder");
    }

    ofstream out(cfg_path);
    if (!out) {
        log(LogLevel::ERROR, ("wpa_supplicant_config: failed to open config file: " + cfg_path.string()).c_str());
        throw runtime_error("wpa_supplicant_config: unable to open config file");
    }

    // wpa_supplicant.conf
    const auto ssid       = client_setup.value("ssid",      string{"wpa3_test"});
    const auto passphrase = client_setup.value("psk",       string{"password123"});

    out << "network={" << '\n';
    // write config
    for (auto it = client_setup.begin(); it != client_setup.end(); ++it) {
        out << it.key() << "=";
        if (it.value().is_string() &&  it.key() != "ssid" && it.key() != "sae_password") {
            out << it.value().get<string>();
        } else {out << it.value().dump();}
        out << "\n";
    }
    out << "}\n";

    out.close();
    log(LogLevel::INFO, ("wpa_supplicant_config: written " + cfg_path.string()).c_str());
    return cfg_path.string();
}
