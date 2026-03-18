#include "setup/scan.h"

#include <libtins-src/include/tins/sniffer.h>
#include "config/global_config.h"
#include "config/RunStatus.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"
#include <fstream>
#include <sstream>

#include "ex_program/external_actors/ExternalConn.h"
#include "system/ip.h"

namespace wpa3_tester{
    using namespace std;
    using nlohmann::json;
    using namespace Tins;
    using namespace filesystem;

    // ---------------- INTERNAL
    // return <string iface; internal_actor >
    vector<ActorPtr> RunStatus::internal_options(){
        vector<ActorPtr> options;
        for (const auto& [iface_name, radio_name, iface_type] : hw_capabilities::list_interfaces(InterfaceType::Wifi)) {
            auto cfg = make_shared<Actor_config>();
            cfg->str_con["iface"] = iface_name;
            cfg->str_con["source"] = "internal";
            cfg->str_con["radio"] = radio_name;
            hw_capabilities::get_nl80211_caps(iface_name, *cfg);
            options.emplace_back(cfg);
        }
        return options;
    }

    void RunStatus::add_actors_by_radio(vector<ActorPtr> &options, const ActorPtr &cfg){
        //cfg->conn->ensure_wifi_ifaces();
        const vector<string> radios = cfg->conn->get_radio_list();
        for (const string& radio_name : radios) {
            const auto actor_cfg = make_shared<Actor_config>(*cfg);
            //actor_cfg->str_con["iface"] = iface;
            //actor_cfg->str_con["mac"]   = cfg->conn->get_mac_address(iface);
            actor_cfg->str_con["driver"] = cfg->conn->get_driver(radio_name);
            actor_cfg->str_con["radio"] = radio_name;
            cfg->conn->get_hw_capabilities(*actor_cfg, radio_name);
            options.emplace_back(actor_cfg);
        }
    }

    // ------------- EXTERNAL
    void RunStatus::solve_new_pdu(PDU& pdu, ActorMap& seen){
        int8_t signal = -1;
        int channel = -1;

        if (auto *radiotap = pdu.find_pdu<RadioTap>()) {
            signal = radiotap->dbm_signal();
            channel = radiotap->channel_freq();
            if (channel > 0) { channel = hw_capabilities::freq_to_channel(channel); }
        }

        const auto add_entity = [&](const string& mac, bool is_ap, const string& ssid = "") {
            const auto actor_config = make_shared<Actor_config>();
            actor_config->str_con["mac"] = mac;
            actor_config->str_con["source"] = "external";
            actor_config->str_con["ssid"] = ssid;
            actor_config->bool_conditions["AP"] = is_ap;
            
            if (channel > 0) {
                actor_config->str_con["channel"] = to_string(channel);
                if (channel >= 1 && channel <= 14) {
                    actor_config->bool_conditions["2_4GHz"] = true;
                } else if (channel >= 36 && channel <= 177) {
                    actor_config->bool_conditions["5GHz"] = true;
                } else if (channel >= 1 && channel <= 233) {
                    actor_config->bool_conditions["6GHz"] = true;
                }
            }
            
            if (signal != -1) {
                actor_config->str_con["signal"] = to_string(signal);
            }

            if (seen.contains(mac)) {
                const auto& existing = seen.at(mac);
                if (!ssid.empty()) existing->str_con["ssid"] = ssid;
                if (channel > 0) existing->str_con["channel"] = to_string(channel);
                if (signal != -1) existing->str_con["signal"] = to_string(signal);
            } else {
                // Add new actor config
                seen.emplace(mac, ActorPtr(actor_config));
            }
        };

        // AP: Beacon
        if (const auto *beacon = pdu.find_pdu<Dot11Beacon>()) {
            const string mac = beacon->addr2().to_string();
            string ssid;
            try { ssid = beacon->ssid(); } catch (...) {}
            
            // Try to get channel from beacon DS parameter
            try {
                if(const auto ds = beacon->search_option(Dot11ManagementFrame::DS_SET)) channel = ds->data_ptr()[0];
            } catch (...) {}
            
            add_entity(mac, true, ssid);
        }
        // AP: Probe Response  
        else if (auto *probe_resp = pdu.find_pdu<Dot11ProbeResponse>()) {
            const string mac = probe_resp->addr2().to_string();
            string ssid;
            try { ssid = probe_resp->ssid(); } catch (...) {}
            add_entity(mac, true, ssid);
        }
        // STA: Probe Request
        else if (auto *probe_req = pdu.find_pdu<Dot11ProbeRequest>()) {
            const string mac = probe_req->addr2().to_string();
            string ssid;
            try { ssid = probe_req->ssid(); } catch (...) {}
            add_entity(mac, false, ssid);
        }
        // Data frames
        else if (auto *data = pdu.find_pdu<Dot11Data>()) {
            const bool to_ds = data->to_ds();
            const bool from_ds = data->from_ds();

            if (to_ds && !from_ds) { // STA → AP
                add_entity(data->addr2().to_string(), false);  // STA
                add_entity(data->addr1().to_string(), true);   // AP
            } else if (!to_ds && from_ds) { // AP → STA
                add_entity(data->addr1().to_string(), false);  // STA
                add_entity(data->addr2().to_string(), true);   // AP
            }
            // WDS/IBSS frames ignored
        }
    }


    vector<ActorPtr> RunStatus::list_external_entities(const string &iface, const int timeout_sec) {
        ActorMap seen; // MAC deduplication

        Sniffer sniffer(iface, SnifferConfiguration{});

        auto handler = [&](PDU &pdu) -> bool {
            try {
                solve_new_pdu(pdu, seen);
            } catch (...) {}
            return true;
        };

        atomic running{true};
        thread timer([&]() {this_thread::sleep_for(chrono::seconds(timeout_sec)); running = false;});

        sniffer.set_timeout(100); // wait for next packet (only for check living sniffer)
        sniffer.sniff_loop([&](PDU& pdu) { handler(pdu); return running.load();});

        timer.join();

        // change format to vector
        return seen | views::values | ranges::to<vector<ActorPtr>>();
    }

    vector<string> scan::parse_csv_line(const string& line) {
        vector<string> fields;
        stringstream ss(line);
        string field;
        while (getline(ss, field, ',')) {
            field.erase(0, field.find_first_not_of(" \t\r\n"));
            field.erase(field.find_last_not_of(" \t\r\n") + 1);
            fields.push_back(field);
        }
        return fields;
    }

    vector<ActorPtr> scan::get_actors_conn_table(const path& conn_table){
        vector<ActorPtr> result;

        if (!exists(conn_table)) {
            log(LogLevel::DEBUG, "Connection table file does not exist: "+conn_table.string());
            return result;
        }

        ifstream file(conn_table);
        if (!file.is_open()) { throw scan_err("Failed to open connection table: %s", conn_table.string().c_str());}
        string line;
        if (!getline(file, line)) {throw scan_err("Empty connection table: "+conn_table.string());}

        // Parse header
        vector<string> headers = parse_csv_line(line);
        map<string, size_t> col_idx;
        for (size_t i = 0; i < headers.size(); ++i) {col_idx[headers[i]] = i;}

        // required columns
        if (!col_idx.contains("whitebox_host") || !col_idx.contains("whitebox_ip")) {
            throw scan_err("Connection table missing required columns (whitebox_host, whitebox_ip): %s",
                conn_table.string().c_str());
        }

        while (getline(file, line)) {
            if (line.empty()) continue;

            vector<string> fields = parse_csv_line(line);
            if (fields.empty()) continue;

            auto cfg = make_shared<Actor_config>();

            // Set fields if column exists and has data
            auto set_field = [&](const string& col_name, const string& cfg_key) {
                if (col_idx.contains(col_name) && col_idx[col_name] <fields.size()) {
                    const string& value = fields[col_idx[col_name]];
                    if (!value.empty()) {
                        cfg->str_con[cfg_key] = value;
                    }
                }
            };

            set_field("whitebox_host", "whitebox_host");
            set_field("whitebox_ip", "whitebox_ip");
            set_field("external_OS", "external_OS");
            set_field("ssh_user", "ssh_user");
            set_field("ssh_port", "ssh_port");
            set_field("ssh_password", "ssh_password");

            result.emplace_back(cfg);
        }

        log(LogLevel::INFO, "Loaded %zu whitebox actors from connection table", result.size());
        return result;
    }

    // return <string radio_name; external_actor >
    vector<ActorPtr> RunStatus::external_wb_options(){
        vector<ActorPtr> options;

        //option1: whitebox_host -> whitebox_ip
        const path conn_table = absolute(path(PROJECT_ROOT_DIR) / "attack_config" /
            get_global_config().at("actors").at("conn_table").get<string>());

        for(auto& cfg : scan::get_actors_conn_table(conn_table)){
            if (!cfg->str_con.at("whitebox_ip").has_value()) {
                const string ip_str = ip::resolve_host(cfg["whitebox_host"]);
                cfg->str_con["whitebox_ip"] = ip_str;
                cfg->str_con["source"] = "external";
                log(LogLevel::DEBUG, "Resolved %s -> %s", cfg["whitebox_host"].c_str(), ip_str.c_str());
            }
            const string ip = cfg["whitebox_ip"];
            if (!ip::ping(ip)) {log(LogLevel::WARNING, "Actor "+ip+" not reachable, skipping");continue;}
            get_or_create_connection(cfg);
            add_actors_by_radio(options, cfg);
        }
        return options;
    }
    vector<ActorPtr> RunStatus::external_bb_options(){
        // option2: blackbox - scan, cant be
        //TODO scan ifaces, scan channels
        return list_external_entities(config.at("actors").at("scan_iface"), 30);
    }

    vector<ActorPtr> create_simulation(){
        throw not_implemented_err("simulation hwsim not implemented");
    }

}
