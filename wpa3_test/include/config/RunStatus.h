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
	AssignmentMap internal_mapping;
	ActorCMap external_actors;
	ActorCMap internal_actors;
	ActorCMap simulation_actors;
    ProcessManager process_manager;

	RunStatus() = default;
    RunStatus(int argc, char ** argv);
    void config_validation();
    void config_requirement();
	std::tuple<ActorCMap, ActorCMap, ActorCMap> parse_requirements();
	void setup_test();

private:
    static std::string findConfigByTestName(const std::string &name);
};
