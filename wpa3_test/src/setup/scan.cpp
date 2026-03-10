#include <libtins-src/include/tins/sniffer.h>
#include <libtins-src/include/tins/dot11/dot11_beacon.h>
#include <libtins-src/include/tins/dot11/dot11_probe.h>
#include <tins/address_range.h>
#include <tins/radiotap.h>
#include <tins/dot11/dot11_data.h>

#include "config/RunStatus.h"
#include "logger/error_log.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester{
    using namespace std;
    using nlohmann::json;
    using namespace Tins;

    // main id is iface
    ActorCMap RunStatus::internal_options(){
        ActorCMap options_map;
        for (const auto& [iface_name, iface_type] : hw_capabilities::list_interfaces()) {
            if(iface_type != InterfaceType::Wifi) continue; //TODO add to selection?
            auto cfg = make_unique<Actor_config>();
            cfg->str_con["iface"] = iface_name;
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

        sniffer.set_timeout(100); // wai for ne packet (only for check living sniffer)
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

    ActorCMap RunStatus::external_options(){
        ActorCMap options_map;

        // option1: scan_iface
        if (config.at("actors").contains("scan_iface")){
            for (const auto& entity :
                list_external_entities(config.at("actors").at("scan_iface"), 30)) {
                auto cfg = make_unique<Actor_config>();
                cfg->str_con["mac"] = entity.mac;
                cfg->str_con["ssid"] = entity.ssid;
                options_map.emplace(entity.mac, std::move(cfg));
            }
        };

        //option2: whitebox_host -> whitebox_ip

        return options_map;
    }

    ActorCMap create_simulation(){
        throw not_implemented_error("simulation hwsim not implemented");
    }

}

