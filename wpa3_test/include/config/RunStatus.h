#pragma once
#include <string>
#include <nlohmann/json.hpp>
#include "Actor_config.h"

using namespace std;

using ActorCMap = unordered_map<string, unique_ptr<Actor_config>>;

class RunStatus {
public:
    nlohmann::json config;
	string configPath;


	RunStatus() = default;
    RunStatus(int argc, char ** argv);
    void config_validation();
    void config_requirement();
	tuple<ActorCMap, ActorCMap, ActorCMap> parse_requirements();

private:
    static string findConfigByTestName(const string &name);
};
