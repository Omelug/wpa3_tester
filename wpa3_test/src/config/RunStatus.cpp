#include "../../include/config/RunStatus.h"
#include <filesystem>
#include "../../include/logger/error_log.h"
#include "../../include/logger/log.h"
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
    attack_run[config["attacker_module"]](runStatus);
};

