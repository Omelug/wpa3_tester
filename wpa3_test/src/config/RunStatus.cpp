#include "config/RunStatus.h"
#include <filesystem>
#include "logger/error_log.h"
#include "logger/log.h"
#include <argparse/argparse.hpp>
#include <string>

#include "attacks/attacks.h"

using namespace std;
using namespace filesystem;

string RunStatus::findConfigByTestName(const string &name){
    //TODO
    throw config_error("Unknown test name: %s", name.c_str());
}

RunStatus::RunStatus(const int argc, char **argv){
	argparse::ArgumentParser program("WPA3_tester", "1.0");

    program.add_argument("--test")
            .help("Find name by test") // TODO add ---test_list to show
            .metavar("NAME");

    program.add_argument("--config")
            .help("Path to config file of test run")
            .metavar("PATH");

    try{
        program.parse_args(argc, argv);
    } catch(const runtime_error &err){
        throw config_error(err.what());
    }

    if(!program.present("--test") && !program.present("--config")){
        throw config_error("--test <test_name> or --config <path> is required");
    }

    if(const auto testName = program.present<string>("--test")){
        configPath = findConfigByTestName(*testName);
    } else{
        configPath = program.get<string>("--config");
    }

    if(!exists(configPath)){
        throw config_error("Config not found: " + configPath);
    }

    log(LogLevel::INFO, "Used config %s", this->configPath.c_str());
}


void RunStatus::run_test(){
    attack_run[config["attacker_module"]](*this);
};

Actor_config& RunStatus::get_actor(const string& actor_name){
    Actor_config* found = nullptr;

    auto check_map = [&](ActorCMap& m, const char* map_name) {
        auto it = m.find(actor_name);
        if (it != m.end()) {
            if (found != nullptr) {
                throw config_error("Actor %s found in multiple maps (including %s)",
                                   actor_name.c_str(), map_name);
            }
            found = it->second.get();
        }
    };

    check_map(external_actors, "external_actors");
    check_map(internal_actors, "internal_actors");
    check_map(simulation_actors, "simulation_actors");

    if (!found) {
        throw config_error("Actor %s not found in any actor map", actor_name.c_str());
    }

    return *found;
}
