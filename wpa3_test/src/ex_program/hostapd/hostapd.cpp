#include <filesystem>
#include <fstream>
#include <stdexcept>
#include "config/global_config.h"
#include "ex_program/hostapd/hostapd_helper.h"
#include "ex_program/hostapd/hostpad.h"
#include "logger/log.h"
#include "observer/observers.h"

namespace wpa3_tester::hostapd{
    using namespace std;
    using namespace filesystem;

    string hostapd_config(const string& run_folder, const nlohmann::json& ap_setup) {

        path folder(run_folder);
        path cfg_path = folder / "hostapd.conf";

        error_code ec;
        create_directories(folder, ec);
        if (ec) {
            log(LogLevel::ERROR, "hostapd_config: failed to ensure run folder: "+folder.string()+":"+ec.message());
            throw runtime_error("hostapd_config: unable to create run folder");
        }

        ofstream hostapd_conf(cfg_path);
        if (!hostapd_conf) {
            log(LogLevel::ERROR, "hostapd_config: failed to open config file: "+cfg_path.string());
            throw runtime_error("hostapd_config: unable to open config file");
        }
        // write config
        for (auto it = ap_setup.begin(); it != ap_setup.end(); ++it) {
            if(it.key() == "version") continue;
            hostapd_conf << it.key() << "=";
            if (it.value().is_string()) {
                hostapd_conf << it.value().get<string>();
            } else {
                hostapd_conf << it.value().dump();
            }
            hostapd_conf << "\n";
        }
        hostapd_conf.close();
        log(LogLevel::INFO, "hostapd_config: written "+cfg_path.string());
        return cfg_path.string();
    }

    string wpa_supplicant_config(const string& run_folder, const nlohmann::json& client_setup) {
        namespace fs = filesystem;

        path folder(run_folder);
        path cfg_path = folder / "wpa_supplicant.conf";

        error_code ec;
        create_directories(folder, ec);
        if (ec) {
            log(LogLevel::ERROR, "wpa_supplicant_config: failed to ensure run folder: "+run_folder+": "+ec.message());
            throw runtime_error("wpa_supplicant_config: unable to create run folder");
        }

        ofstream out(cfg_path);
        if (!out) {
            log(LogLevel::ERROR, "wpa_supplicant_config: failed to open config file: "+cfg_path.string());
            throw runtime_error("wpa_supplicant_config: unable to open config file");
        }

        // wpa_supplicant.conf

        out << "network={" << '\n';
        // write config
        for (auto it = client_setup.begin(); it != client_setup.end(); ++it) {
            if(it.key() == "version") continue;
            out << "\t" << it.key() << "=";
            if (it.value().is_string() &&  it.key() != "ssid" && it.key() != "sae_password") {
                out << it.value().get<string>();
            } else {out << it.value().dump();}
            out << "\n";
        }
        out << "}\n";

        out.close();
        log(LogLevel::INFO, "wpa_supplicant_config: written "+cfg_path.string());
        return cfg_path.string();
    }

    void run_hostapd(RunStatus& run_status, const string &actor_name){
        nlohmann::json program_config = run_status.config.at("actors").at(actor_name).at("setup").at("program_config");
        const string hostapd_config_path = hostapd_config(
            run_status.run_folder,
            program_config);
        run_status.get_actor(actor_name)->str_con["ssid"] = program_config["ssid"].get<string>();

        string version = "";
        if (program_config.contains("version") && !program_config["version"].is_null()) {
            version = program_config["version"].get<string>();
        }

        vector<string> command = {"sudo"};
        observer::add_nets(run_status,command, actor_name);

        command.insert(command.end(), {
            get_hostapd(version),
            //"-dd",
            "-i", run_status.get_actor(actor_name)["iface"],
            hostapd_config_path,
        });

        run_status.process_manager.run(actor_name,command);
    }

    void run_wpa_supplicant(RunStatus& run_status, const string &actor_name){
        nlohmann::json program_config = run_status.config.at("actors").at(actor_name).at("setup").at("program_config");

        string version = "";
        if (program_config.contains("version") && !program_config["version"].is_null()) {
            version = program_config["version"].get<string>();
        }

        const string wpa_supp_config_path = wpa_supplicant_config(
            run_status.run_folder,
            program_config);

        vector<string> command = {"sudo"};
        observer::add_nets(run_status,command, actor_name);

        command.insert(command.end(), {
            get_wpa_supplicant(version),
            //"-dd",
            "-i", run_status.get_actor(actor_name)["iface"],
            "-c", wpa_supp_config_path
        });
        run_status.process_manager.run(actor_name, command);
    }
}
