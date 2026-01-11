#include "ex_program/hostapd/hostpad.h"
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include "logger/log.h"
#include "observer/observers.h"

namespace wpa3_tester{
    using namespace std;
    using namespace filesystem;
    string hostapd_config(const string& run_folder, const nlohmann::json& ap_setup) {

        path folder(run_folder);
        path cfg_path = folder / "hostapd.conf";

        error_code ec;
        create_directories(folder, ec);
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

        path folder(run_folder);
        path cfg_path = folder / "wpa_supplicant.conf";

        error_code ec;
        create_directories(folder, ec);
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
            out << "\t" << it.key() << "=";
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
    void run_hostapd(RunStatus& run_status, const string &actor_name){
        const string hostapd_config_path = hostapd_config(
            run_status.run_folder,
            run_status.config["actors"][actor_name]["setup"]["program_config"]);

        vector<string> command = {"sudo"};
        observer::add_nets(run_status,command, actor_name);

        command.insert(command.end(), {
            "hostapd",
            "-i", run_status.get_actor(actor_name)["iface"],
            hostapd_config_path,
        });

        run_status.process_manager.run(actor_name,command);
    }

    void run_wpa_supplicant(RunStatus& run_status, const string &actor_name){
        const string wpa_supp_config_path = wpa_supplicant_config(
            run_status.run_folder,
            run_status.config["actors"][actor_name]["setup"]["program_config"]
            );

        vector<string> command = {"sudo"};
        observer::add_nets(run_status,command, actor_name);

        command.insert(command.end(), {
            "wpa_supplicant",
            "-i", run_status.get_actor(actor_name)["iface"],
            "-c", wpa_supp_config_path
        });
        run_status.process_manager.run(actor_name, command);
    }

}
