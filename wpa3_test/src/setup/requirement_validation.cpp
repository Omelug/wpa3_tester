#include "config/RunStatus.h"
#include "config/Actor_config.h"
#include "system/hw_capabilities.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "system/iface.h"

using namespace std;
using nlohmann::json;
namespace wpa3_tester{
    ActorCMap RunStatus::scan_internal() const{
        ActorCMap options_map;

        for (const auto& [iface_name, iface_type] : hw_capabilities::list_interfaces(*this)) {
            if(iface_type != InterfaceType::Wifi) continue; //TODO add to selection?
            json actor_json;
            actor_json["selection"]["iface"] = iface_name;
            auto cfg = make_unique<Actor_config>(actor_json);
            hw_capabilities::get_nl80211_caps(iface_name, *cfg);
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
            if(source == "internal") {in_map[actor_name] = std::move(config_ptr); continue;}
            if(source == "simulation") {sim_map[actor_name] = std::move(config_ptr); continue;}
            throw config_error("Unknown source %s in actor: %s", source.c_str(), actor_name.c_str());
        }

        return std::make_tuple(
           std::move(ex_map),
           std::move(in_map),
           std::move(sim_map)
       );
    }


    void cleanup_all_namespaces() {
        log(LogLevel::INFO, "Global cleanup: Safely returning interfaces and removing namespaces...");

        //TODO kill all?
        system("sudo pkill -SIGTERM iperf3 wpa_supplicant hostapd tshark mausezahn 2>/dev/null || true");
        this_thread::sleep_for(std::chrono::milliseconds(500));
        //TODO paths only for debian
        system("for ns in $(ls /var/run/netns/ 2>/dev/null); do "
               "  for phy in $(sudo ip netns exec $ns iw phy | grep wiphy | awk '{print $2}'); do "
               "    sudo ip netns exec $ns iw phy phy$phy set netns 1; "
               "  done; "
               "done");
        system("ls /var/run/netns/ | xargs -I {} sudo ip netns del {} 2>/dev/null");

        log(LogLevel::INFO, "Cleanup complete. Waiting for kernel to stabilize...");
        this_thread::sleep_for(std::chrono::seconds(2));
    }


    void RunStatus::config_requirement() {
        cleanup_all_namespaces();

        //check actors are not empty
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

        // ------------------ INTERNAL ---------------------------
        const ActorCMap options_internal =  scan_internal();
        //find interface mapping
        internal_mapping = hw_capabilities::check_req_options(internal_actors, options_internal);

        // setup by mapping
        for (auto &[actor_name, actor] : internal_actors) {
            const string &actorName = actor_name;
            auto resIt = internal_mapping.find(actorName);
            if (resIt == internal_mapping.end()) {continue;}

            //TODO move to
            optional<string> netns_opt;
            if (config["actors"][actorName].contains("netns")) {
                netns_opt = config["actors"][actorName]["netns"].get<string>();
                const string& ns_name = netns_opt.value();
                string create_ns_cmd = "sudo ip netns add " + ns_name + " 2>/dev/null || true";
                system(create_ns_cmd.c_str());
                string lo_up_cmd = "sudo ip netns exec " + ns_name + " ip link set lo up";
                system(lo_up_cmd.c_str());
            }

            const string &opt_iface = resIt->second;
            auto optIt = options_internal.find(opt_iface);
            if (optIt == options_internal.end() || !optIt->second) {
                throw config_error("Selected option %s for actor %s not found in options",
                    opt_iface.c_str(), actorName.c_str());
            }

            // create interface object (with optional netns from config)
            iface ifc{opt_iface, netns_opt};
            ifc.cleanup();

            //---------------  set mode based on actor requirements -------------------
            if (actor->bool_conditions.at("monitor").value_or(false)) {ifc.set_monitor_mode();}
            if (actor->bool_conditions.at("AP").value_or(false)) {ifc.set_managed_mode();}

            if (config["actors"][actorName].contains("channel")) {
                ifc.set_channel(config["actors"][actorName]["channel"]);
            }

            actor = make_unique<Actor_config>(*optIt->second);
        }

        // TODO: simulation -> check hw compatibility
        //ActorCMap options_external =  create_simulation();

    }
}