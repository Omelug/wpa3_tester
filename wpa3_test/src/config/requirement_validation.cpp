#include "../../include/config/RunStatus.h"
#include "../../include/config/Actor_config.h"
#include "../../include/config/hw_capabilities.h"
#include "../../include/logger/error_log.h"
#include "../../include/logger/log.h"
#include <iostream>

using namespace std;
using nlohmann::json;


ActorCMap scan_internal(){
    ActorCMap options_map;
    //hw_capabilities::ensure_iw_cached();
    //TODO parse_iw
    return std::move(options_map);
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

    //hw_capabilities::check_req_options(internal, options_internal);

    // TODO: simulation -> check hw compatibility
    //ActorCMap options_external =  create_simulation();

    //hw_capabilities::reset();
}