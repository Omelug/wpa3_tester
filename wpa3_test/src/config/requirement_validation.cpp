#include "../../include/config/RunStatus.h"
#include "../../include/config/Actor_config.h"
#include "../../include/config/hw_capabilities.h"
#include "../../include/logger/error_log.h"
#include "../../include/logger/log.h"

using namespace std;
using nlohmann::json;

ActorCMap RunStatus::scan_internal() {
    ActorCMap options_map;

    for (auto [iface_name, iface_type] : hw_capabilities::list_interfaces(*this)) {
        if(iface_type != InterfaceType::Wifi) continue; //TODO
        json actor_json;
        actor_json["selection"]["iface"] = iface_name;
        auto cfg = std::make_unique<Actor_config>(actor_json);

        cfg->mac = hw_capabilities::read_sysfs(iface_name, "address");
        cfg->driver = hw_capabilities::get_driver_name(iface_name);

        NlCaps caps =  hw_capabilities::get_nl80211_caps(iface_name);

        cfg->bool_conditions["monitor"]   = caps.monitor;
        cfg->bool_conditions["2_4GHz"]    = caps.band24;
        cfg->bool_conditions["5GHz"]      = caps.band5;
        cfg->bool_conditions["WPA-PSK"]   = caps.wpa2_psk;
        cfg->bool_conditions["WPA3-SAE"]  = caps.wpa3_sae;

        options_map.emplace(iface_name, std::move(cfg));
    }
    return options_map;
}

tuple<ActorCMap, ActorCMap, ActorCMap> RunStatus::parse_requirements() {
    ActorCMap ex_map, in_map, sim_map;

    const json &actors = config["actors"];
    for (auto it = actors.begin(); it != actors.end(); ++it) {
        const string& actor_name = it.key();
        const json &actor = it.value();

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

    // persist maps in RunStatus
    external_actors  = std::move(external);
    internal_actors  = std::move(internal);
    simulation_actors = std::move(simulation);

    log_actor_map("external", external_actors);
    log_actor_map("internal", internal_actors);
    log_actor_map("simulation", simulation_actors);

    const ActorCMap options_internal =  scan_internal();

    //find interface mapping
    internal_mapping = hw_capabilities::check_req_options(internal_actors, options_internal);

    // setup by mapping
    for (auto &[actor_name, actor] : internal_actors) {
        const string &actorName = actor_name;
        auto resIt = internal_mapping.find(actorName);
        if (resIt == internal_mapping.end()) {continue;}

        const string &opt_iface = resIt->second;
        auto optIt = options_internal.find(opt_iface);
        if (optIt == options_internal.end() || !optIt->second) {
            throw config_error("Selected option %s for actor %s not found in options",
                opt_iface.c_str(), actorName.c_str());
        }

        hw_capabilities::cleanup_interface(opt_iface);

        //---------------  set mode based on actor requirements -------------------
        if (actor->bool_conditions.at("monitor").value_or(false)) {
                hw_capabilities::set_monitor_mode(opt_iface);
        }

        if (config["actors"][actorName]["type"] == "AP") {
            hw_capabilities::set_ap_mode(opt_iface);
        }
        //TODO other types

        if (config["actors"][actorName].contains("channel")) {
            hw_capabilities::set_channel(opt_iface, config["actors"][actorName]["channel"]);
        }

        // save option properties to actor
        actor = make_unique<Actor_config>(*optIt->second);
    }

	//TODO setup_requirements(internal_actors);

	//log_actor_configs(internal_actors);

    // TODO: simulation -> check hw compatibility
    //ActorCMap options_external =  create_simulation();

    //hw_capabilities::reset();
}