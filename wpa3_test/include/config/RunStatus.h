#pragma once
#include <string>
#include <map>
#include <unordered_map>
#include <memory>
#include <tuple>
#include <nlohmann/json.hpp>
#include "Actor_config.h"
#include "ProcessManager.h"

class Actor_config;
using ActorCMap = std::unordered_map<std::string, std::unique_ptr<Actor_config>>;
using AssignmentMap = std::map<std::string,std::string>;

class RunStatus {
public:
    nlohmann::json config;
    std::string run_folder;
    std::string configPath;

    //actors
	ActorCMap external_actors;
	ActorCMap internal_actors;
	ActorCMap simulation_actors;

    //mapping actor->interface
    AssignmentMap internal_mapping;
    //AssignmentMap external_mapping;
    //AssignmentMap simulation_mapping;


    ProcessManager process_manager;

	RunStatus() = default;
    RunStatus(int argc, char ** argv);

private:
    static std::string findConfigByTestName(const std::string &name);

    // to scan available interfaces
    ActorCMap scan_internal() const;
    //ActorCMap scan_external() const;
    //ActorCMap scan_simulation() const;

    std::tuple<ActorCMap, ActorCMap, ActorCMap> parse_requirements();

public:
    void config_validation();
    void config_requirement();
    void setup_test();
    void run_test();

};
