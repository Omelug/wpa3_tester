#include "setup/scan.h"

#include <libtins-src/include/tins/sniffer.h>
#include "config/global_config.h"
#include "config/RunStatus.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"
#include <fstream>
#include <sstream>

#include "system/ip.h"

namespace wpa3_tester{
    using namespace std;
    using nlohmann::json;
    using namespace Tins;
    using namespace filesystem;

    // ---------------- INTERNAL
    // return <string iface; internal_actor >
    ActorCMapU RunStatus::internal_options(){
        ActorCMapU options_map;
        for (const auto& [iface_name, iface_type] : hw_capabilities::list_interfaces()) {
            if(iface_type != InterfaceType::Wifi) continue; //TODO add to selection?
            auto cfg = make_unique<Actor_config>();
            cfg->str_con["iface"] = iface_name;
            cfg->str_con["source"] = "internal";
            hw_capabilities::get_nl80211_caps(iface_name, *cfg);
            options_map.emplace(iface_name, std::move(cfg));
        }
        return options_map;
    }

    // ------------- EXTERNAL
    void RunStatus::solve_new_pdu(PDU& pdu, map<string, ExternalEntity>& seen){
        int signal = 0;
        if (pdu.find_pdu<RadioTap>()) {
            signal = pdu.rfind_pdu<RadioTap>().dbm_signal();
        }

        // --- AP: Beacon ---
        if (auto *beacon = pdu.find_pdu<Dot11Beacon>()) {
            const string mac = beacon->addr2().to_string();
            if (!seen.contains(mac)) {
                ExternalEntity e;
                e.mac    = mac;
                e.is_ap  = true;
                e.signal = signal;
                try { e.ssid = beacon->ssid(); } catch (...) {}
                try {
                    auto ds = beacon->search_option(Dot11ManagementFrame::DS_SET);
                    e.channel = ds->data_ptr()[0];
                } catch (...) {}
                seen[mac] = e;
            }
        }

        // --- AP: Probe Response ---
        else if (auto *probe_resp = pdu.find_pdu<Dot11ProbeResponse>()) {
            const string mac = probe_resp->addr2().to_string();
            if (!seen.contains(mac)) {
                ExternalEntity e;
                e.mac    = mac;
                e.is_ap  = true;
                e.signal = signal;
                try { e.ssid = probe_resp->ssid(); } catch (...) {}
                seen[mac] = e;
            }
        }

        // --- STA: Probe Request ---
        else if (auto *probe_req = pdu.find_pdu<Dot11ProbeRequest>()) {
            const string mac = probe_req->addr2().to_string();
            if (!seen.contains(mac)) {
                ExternalEntity e;
                e.mac    = mac;
                e.is_ap  = false;
                e.signal = signal;
                try { e.ssid = probe_req->ssid(); } catch (...) {}
                seen[mac] = e;
            }
        }
        else if (auto *data = pdu.find_pdu<Dot11Data>()) {
            const bool to_ds   = data->to_ds();
            const bool from_ds = data->from_ds();

            string sta_mac;
            string ap_mac;

            if (to_ds && !from_ds) { // STA → AP
                sta_mac = data->addr2().to_string();
                ap_mac  = data->addr1().to_string();
            } else if (!to_ds && from_ds) { // AP → STA
                sta_mac = data->addr1().to_string();
                ap_mac  = data->addr2().to_string();
            } else {
                // to_ds && from_ds = WDS bridge — ignore
                // !to_ds && !from_ds = IBSS — ignore
                return;
            }

            // STA
            if (!seen.contains(sta_mac)) {
                ExternalEntity e;
                e.mac   = sta_mac;
                e.is_ap = false;
                seen[sta_mac] = e;
            }

            // AP (ssid not known)
            if (!seen.contains(ap_mac)) {
                ExternalEntity e;
                e.mac   = ap_mac;
                e.is_ap = true;
                seen[ap_mac] = e; //FIXME this rewrite valid ssid
            }
        }
    }


    vector<ExternalEntity> RunStatus::list_external_entities(const string &iface, const int timeout_sec) {
        map<string, ExternalEntity> seen; // MAC deduplication

        Sniffer sniffer(iface, SnifferConfiguration{});

        auto handler = [&](PDU &pdu) -> bool {
            try {
                solve_new_pdu(pdu, seen);
            } catch (...) {}
            return true;
        };
        atomic running{true};
        thread timer([&]() {
            this_thread::sleep_for(chrono::seconds(timeout_sec));
            running = false;
        });

        sniffer.set_timeout(100); // wait for next packet (only for check living sniffer)
        sniffer.sniff_loop([&](PDU& pdu) {
            handler(pdu);
            return running.load();
        });

        timer.join();

        vector<ExternalEntity> result;
        result.reserve(seen.size());
        for (auto &entity: seen | views::values) result.push_back(entity);
        return result;
    }

    vector<string> scan::parse_csv_line(const string& line) {
        vector<string> fields;
        stringstream ss(line);
        string field;
        while (getline(ss, field, ',')) {
            // Trim whitespace
            field.erase(0, field.find_first_not_of(" \t\r\n"));
            field.erase(field.find_last_not_of(" \t\r\n") + 1);
            fields.push_back(field);
        }
        return fields;
    }

    vector<unique_ptr<Actor_config>> scan::get_actors_conn_table(const path& conn_table){
        vector<unique_ptr<Actor_config>> result;

        if (!exists(conn_table)) {
            log(LogLevel::DEBUG, "Connection table file does not exist: %s", conn_table.string().c_str());
            return result;
        }

        ifstream file(conn_table);
        if (!file.is_open()) { throw scan_error("Failed to open connection table: %s", conn_table.string().c_str());}
        string line;
        if (!getline(file, line)) {throw scan_error("Empty connection table: " + conn_table.string());}

        // Parse header
        vector<string> headers = parse_csv_line(line);
        map<string, size_t> col_idx;
        for (size_t i = 0; i < headers.size(); ++i) {col_idx[headers[i]] = i;}

        // required columns
        if (!col_idx.contains("whitebox_host") || !col_idx.contains("whitebox_ip")) {
            throw scan_error("Connection table missing required columns (whitebox_host, whitebox_ip): %s",
                conn_table.string().c_str());
        }

        while (getline(file, line)) {
            if (line.empty()) continue;

            vector<string> fields = parse_csv_line(line);
            if (fields.empty()) continue;

            auto cfg = make_unique<Actor_config>();

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

            result.push_back(std::move(cfg));
        }

        log(LogLevel::INFO, "Loaded %zu whitebox actors from connection table", result.size());
        return result;
    }

    // return <string MAC; external_actor >
    ActorCMapU RunStatus::external_wb_options(){
        ActorCMapU options_map;

        //option1: whitebox_host -> whitebox_ip
        const path conn_table = absolute(path(PROJECT_ROOT_DIR) / "attack_config" /
            get_global_config().at("actors").at("conn_table").get<string>());

        for(auto& cfg : scan::get_actors_conn_table(conn_table)){
            if (!cfg->str_con.at("whitebox_ip").has_value()) {
                const string ip_str = ip::resolve_host((*cfg)["whitebox_host"]);
                cfg->str_con["whitebox_ip"] = ip_str;
                cfg->str_con["source"] = "external";
                log(LogLevel::DEBUG, "Resolved %s -> %s", (*cfg)["whitebox_host"].c_str(), ip_str.c_str());
            }
            const string ip = (*cfg)["whitebox_ip"];
            if (!ip::ping(ip)) {log(LogLevel::WARNING, "Actor %s not reachable, skipping", ip.c_str());continue;}

            cfg->str_con["mac"] = ip::get_mac_by_ip(ip);
            options_map.emplace((*cfg)["mac"], std::move(cfg));
        }


        return options_map;
    }
    ActorCMapU RunStatus::external_bb_options(){
        ActorCMapU options_map;
        // option2: blackbox - scan, cant be
        //TODO get channels from actors and scan only these if not actor without it
        /*for (const auto& entity :
            list_external_entities(config.at("actors").at("scan_iface"), 30)) {
            auto cfg = make_unique<Actor_config>();
            cfg->str_con["mac"] = entity.mac;
            cfg->str_con["ssid"] = entity.ssid;
            if(entity.is_ap){cfg->bool_conditions["AP"] = true;}
            options_map.emplace(entity.mac, std::move(cfg));
        }*/
        return options_map;
    }
    ActorCMap create_simulation(){
        throw not_implemented_error("simulation hwsim not implemented");
    }

}

