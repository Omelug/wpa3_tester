#include <filesystem>
#include <fstream>
#include <stdexcept>
#include "config/global_config.h"
#include "ex_program/hostapd/hostapd_helper.h"
#include "ex_program/hostapd/hostapd.h"

#include "logger/error_log.h"
#include "logger/log.h"
#include "observer/observers.h"

namespace wpa3_tester::hostapd{
    using namespace std;
    using namespace filesystem;
    using namespace nlohmann;

    static string get_field_or_parse(
  const json& program_config,
  const string& key,
  const string& config_path,
  bool is_int,
  const function<string(const string&)>& parse_from_file)
    {
        if (program_config.contains(key)) {
            if (is_int) return to_string(program_config[key].get<int>());
            return program_config[key].get<string>();
        }
        if (!config_path.empty()) {
            try {
                return parse_from_file(config_path);
            } catch (...) {}
        }
        throw config_err("Field '" + key + "' not found in config or file: " + config_path);
    }

    static string parse_key_from_file(const string& config_path, const string& key) {
        ifstream f(config_path);
        string line;
        while (getline(f, line)) {
            if (line.starts_with(key + "="))
                return line.substr(key.size() + 1);
        }
        throw config_err("Key '" + key + "' not found in file: " + config_path);
    }

    string get_ssid(const json& program_config, const string& config_path) {
        return get_field_or_parse(program_config, "ssid", config_path, false,
            [](const string& p) { return parse_key_from_file(p, "ssid"); });
    }

    string get_channel(const json& program_config, const string& config_path) {
        return get_field_or_parse(program_config, "channel", config_path, true,
            [](const string& p) { return parse_key_from_file(p, "channel"); });
    }


    // --------------- HOSTAPD -----------------------
    string hostapd_config(const string& run_folder, const string &actor_name, const json& ap_setup, const path &config_folder) {

        path folder(run_folder);
        path cfg_path = folder / (actor_name+"_hostapd.conf");

        error_code ec;
        create_directories(folder, ec);
        if (ec) {
            log(LogLevel::ERROR, "hostapd_config: failed to ensure run folder: "+folder.string()+":"+ec.message());
            throw runtime_error("hostapd_config: unable to create run folder");
        }

        if(ap_setup.contains("hostapd_path")){
            path hostapd_path = ap_setup["hostapd_path"].get<string>();
            path src = hostapd_path.is_absolute() ? hostapd_path : config_folder / hostapd_path;
            copy_file(src, cfg_path, copy_options::overwrite_existing);
            return cfg_path.string();
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


    void run_hostapd(RunStatus& rs, const string &actor_name){
        json program_config = rs.config.at("actors").at(actor_name).at("setup").at("program_config");
        const string hostapd_config_path = hostapd_config(
            rs.run_folder,
            actor_name,
            program_config, path(rs.config_path).parent_path());
        rs.get_actor(actor_name)->str_con["ssid"] = get_ssid(program_config, hostapd_config_path);
        rs.get_actor(actor_name)->str_con["channel"] = get_channel(program_config, hostapd_config_path);

        string version;
        if (program_config.contains("version") && !program_config["version"].is_null()) {
            version = program_config["version"].get<string>();
        }

        vector<string> command = {"sudo"};
        observer::add_nets(rs,command, actor_name);

        command.insert(command.end(), {
            get_hostapd(version),
            //"-dd",
            "-i", rs.get_actor(actor_name)["iface"],
            hostapd_config_path,
        });
        rs.process_manager.run(actor_name,command, rs.run_folder);
    }


    // --------- WPA_SUPPLICANT ---------------
    string wpa_supplicant_config(const string& run_folder, const string& actor_name, const json& client_setup, const path &config_folder) {

        path folder(run_folder);
        path cfg_path = folder / (actor_name+"_wpa_supplicant.conf");

        error_code ec;
        create_directories(folder, ec);
        if (ec) {
            log(LogLevel::ERROR, "wpa_supplicant_config: failed to ensure run folder: "+run_folder+": "+ec.message());
            throw runtime_error("wpa_supplicant_config: unable to create run folder");
        }

        if(client_setup.contains("wpa_supplicant_path")){
            path hostapd_path = client_setup["wpa_supplicant_path"].get<string>();
            path src = hostapd_path.is_absolute() ? hostapd_path : config_folder / hostapd_path;
            copy_file(src, cfg_path, copy_options::overwrite_existing);
            return cfg_path.string();
        }

        ofstream out(cfg_path);
        if (!out) {
            log(LogLevel::ERROR, "wpa_supplicant_config: failed to open config file: "+cfg_path.string());
            throw runtime_error("wpa_supplicant_config: unable to open config file");
        }

        // wpa_supplicant.conf
        static const set<string> quoted_keys = {"ssid", "sae_password", "psk", "identity", "password"};

        out << "network={\n";
        for (auto it = client_setup.begin(); it != client_setup.end(); ++it) {
            if (it.key() == "version") continue;
            out << "\t" << it.key() << "=";
            if (it.value().is_string() && !quoted_keys.contains(it.key())) {
                out << it.value().get<string>();
            } else {
                out << it.value().dump();
            }
            out << "\n";
        }
        out << "}\n";

        out.close();
        log(LogLevel::INFO, "wpa_supplicant_config: written "+cfg_path.string());
        return cfg_path.string();
    }

    void run_wpa_supplicant(RunStatus& rs, const string &actor_name){
        json program_config = rs.config.at("actors").at(actor_name).at("setup").at("program_config");

        string version;
        if (program_config.contains("version") && !program_config["version"].is_null()) {
            version = program_config["version"].get<string>();
        }

        const string wpa_supp_config_path = wpa_supplicant_config(
            rs.run_folder,
            actor_name,
            program_config, path(rs.config_path).parent_path());

        vector<string> command = {"sudo"};
        observer::add_nets(rs, command, actor_name);

        command.insert(command.end(), {
            get_wpa_supplicant(version),
            //"-dd",
            "-i", rs.get_actor(actor_name)["iface"],
            "-c", wpa_supp_config_path
        });
        rs.process_manager.run(actor_name, command, rs.run_folder);
    }

    // --------- HOSTAPD_MANA ---------
    void run_hostapd_mana(RunStatus& rs, const string &actor_name){

        const path hostapd_config_config_path = path(rs.run_folder)/(actor_name+"_hostapd_mana.conf");

        json program_config = rs.config.at("actors").at(actor_name).at("setup").at("program_config");
        auto rogue_ap_setup = rs.config.at("actors").at(actor_name).at("setup").at("program");
        if(rogue_ap_setup.contains("hostapd-mana_path")){
            const path hostapd_path = rogue_ap_setup["hostapd-mana_path"].get<string>();
            const path src = hostapd_path.is_absolute() ? hostapd_path : path(rs.config_path).parent_path() / hostapd_path;
            copy_file(src, hostapd_config_config_path, copy_options::overwrite_existing);
        }

        rs.get_actor(actor_name)->str_con["ssid"] = get_ssid(program_config, hostapd_config_config_path);
        rs.get_actor(actor_name)->str_con["channel"] = get_channel(program_config, hostapd_config_config_path);

        vector<string> command = {"sudo"};
        observer::add_nets(rs,command, actor_name);
        command.insert(command.end(), {
            "hostapd-mana",
            "-i", rs.get_actor(actor_name)["iface"],
            hostapd_config_config_path,
        });
        rs.process_manager.run(actor_name,command, rs.run_folder);
    }
}
