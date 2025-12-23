#include "../../include/config/RunStatus.h"
#include "../../include/config/Actor_config.h"
#include "../../include/config/hw_capabilities.h"
#include "../../include/logger/error_log.h"
#include "../../include/logger/log.h"
#include <iostream>
#include <sstream>

using namespace std;
using nlohmann::json;

// Helper: parse iw phy <phy> info text into capability flags
struct IfaceCapabilities {
    bool monitor = false;
    bool has_24 = false;
    bool has_5 = false;
    bool wpa_psk = false;
    bool wpa3_sae = false;
};

static IfaceCapabilities parse_iw_phy_info(const std::string& text) {
    IfaceCapabilities caps;
    if (text.empty()) return caps;

    istringstream iss(text);
    string line;
    bool in_if_modes = false;

    while (getline(iss, line)) {
        // interface modes
        if (line.find("Supported interface modes:") != string::npos) {
            in_if_modes = true;
            continue;
        }
        if (in_if_modes) {
            if (line.find("\t") == string::npos && line.find("  ") == string::npos) {
                in_if_modes = false;
            } else if (line.find("monitor") != string::npos) {
                caps.monitor = true;
            }
        }

        // crude freq detection
        auto mhz_pos = line.find(" MHz");
        if (mhz_pos != string::npos) {
            size_t start = line.rfind(' ', mhz_pos);
            if (start != string::npos && start + 1 < mhz_pos) {
                try {
                    int freq = stoi(line.substr(start + 1, mhz_pos - (start + 1)));
                    if (freq >= 2000 && freq < 3000) caps.has_24 = true;
                    if (freq >= 4900 && freq < 6000) caps.has_5 = true;
                } catch (...) {
                    // ignore parse errors
                }
            }
        }

        // very simple WPA capability hints (only if present)
        if (line.find("WPA-PSK") != string::npos || line.find("WPA2-PSK") != string::npos) {
            caps.wpa_psk = true;
        }
        if (line.find("SAE") != string::npos || line.find("WPA3") != string::npos) {
            caps.wpa3_sae = true;
        }
    }

    return caps;
}

// Parse cached `iw dev` output into ActorCMap of internal options, then
// for each iface run `iw phy <phy> info` and fill capability flags.
static ActorCMap parse_iw_to_actors_with_caps(const std::string& iw_dev_output) {
    ActorCMap result;
    if (iw_dev_output.empty()) {
        return result;
    }

    istringstream iss(iw_dev_output);
    string line;

    string current_phy_name;
    const string phy_prefix = "phy#";
    const string iface_prefix = "\tInterface ";

    while (getline(iss, line)) {
        if (line.rfind(phy_prefix, 0) == 0) {
            current_phy_name = line.substr(phy_prefix.size());
            continue;
        }
        if (line.rfind(iface_prefix, 0) == 0 && !current_phy_name.empty()) {
            string iface = line.substr(iface_prefix.size());
            while (!iface.empty() && isspace(static_cast<unsigned char>(iface.back()))) {
                iface.pop_back();
            }

            // resolve phy for this iface and query iw phy <phy> info
            string phy_id = hw_capabilities::get_phy_from_iface(iface);
            string iw_phy_info;
            if (!phy_id.empty()) {
                string cmd = "iw phy phy" + phy_id + " info";
                iw_phy_info = hw_capabilities::run_command(cmd);
            }

            IfaceCapabilities caps = parse_iw_phy_info(iw_phy_info);

            json actor;
            actor["selection"]["iface"] = iface;
            auto &cond = actor["selection"]["condition"];
            cond = json::array();
            if (caps.monitor)  cond.push_back("monitor");
            if (caps.has_24)   cond.push_back("2_4Gz");
            if (caps.has_5)    cond.push_back("5GHz");
            if (caps.wpa_psk)  cond.push_back("WPA-PSK");
            if (caps.wpa3_sae) cond.push_back("WPA3-SAE");

            auto cfg = std::make_unique<Actor_config>(actor);
            result.emplace(iface, std::move(cfg));
        }
    }

    return result;
}

ActorCMap scan_internal(){
    ActorCMap options_map;
    hw_capabilities::ensure_iw_cached();

    std::string iw_dev_output = hw_capabilities::get_iw_cache();
    if (iw_dev_output.empty()) {
        log(LogLevel::ERROR, "iw dev returned empty output; no internal interfaces detected");
        return options_map;
    }

    options_map = parse_iw_to_actors_with_caps(iw_dev_output);
    log(LogLevel::DEBUG, "Parsed %zu internal interface option(s) from iw dev/iw phy", options_map.size());
    return options_map;
}

tuple<ActorCMap, ActorCMap, ActorCMap> RunStatus::parse_requirements() {
    ActorCMap ex_map, in_map, sim_map;

    const json &actors = config["actors"];
    for (auto it = actors.begin(); it != actors.end(); ++it) {
        const string& actor_name = it.key();
        const json &actor = it.value();

        log(LogLevel::DEBUG, "Parsing Actor: %s", actor_name.c_str());

        string source = actor["source"];
        auto config_ptr = make_unique<Actor_config>(actor);

        if(source == "external") {ex_map[actor_name] = std::move(config_ptr); continue;}
        if (source == "internal") { in_map[actor_name] = std::move(config_ptr); continue; }
        if (source == "simulation") {sim_map[actor_name] = std::move(config_ptr); continue; }
		throw config_error("Unknown source %s in actor: %s", source.c_str(), actor_name.c_str());
    }
    return std::make_tuple(
       std::move(ex_map),
       std::move(in_map),
       std::move(sim_map)
   );
}

void RunStatus::config_requirement() {

    //check tor are not empty
    if (!config.contains("actors") || !config["actors"].is_object()) {
        throw config_error("Actors are not in: %s", config.dump().c_str());
    }

   	 //todo get map from
    auto [external, internal, simulation] = parse_requirements();

    log_actor_map("external", external);
    log_actor_map("internal", internal);
    log_actor_map("simulation", simulation);

    //ActorCMap options_external =  scan_external();

    ActorCMap options_internal =  scan_internal();
   	hw_capabilities::check_req_options(internal, options_internal);

    // TODO: simulation -> check hw compatibility
    //ActorCMap options_external =  create_simulation();

    //hw_capabilities::reset();
}