#include <iostream>
#include "config/RunStatus.h"
#include <csignal>
#include <thread>
#include <argparse/argparse.hpp>
#include <yaml-cpp/yaml.h>

#include "logger/error_log.h"
#include "logger/log.h"
#include "system/ProcessManager.h"

using namespace wpa3_tester;
using namespace std;
using namespace filesystem;

static RunStatus* globalRunStatus = nullptr;

void signal_handler(const int signum) {
    if (globalRunStatus) {globalRunStatus->process_manager.stop_all();}
    exit(signum);
}

unordered_map<string, string> scan_attack_configs() {
    unordered_map<string, string> test_map;
    path attack_config_dir = path(PROJECT_ROOT_DIR)/ "attack_config";

    const string directory = "./attack_config";
    if (!exists(attack_config_dir) || !is_directory(attack_config_dir)) {return test_map;}

    for (const auto& entry : recursive_directory_iterator(attack_config_dir)) {
        const auto& path = entry.path();
        string filename = path.filename().string();

        if (filename.ends_with(".schema.yaml") || path.extension() != ".yaml") {continue;}

        try {
            YAML::Node config = YAML::LoadFile(path.string());
            if (config["name"]) {
                auto test_name = config["name"].as<string>();
                if (test_map.contains(test_name)) {
                    throw config_error("Configs " + test_map[test_name] +
                                       " and " + path.string() + " have same name!");
                }
                test_map[test_name] = path.string();
            }
        } catch (const YAML::Exception& e) {throw config_error("Invalid name {}", e.what());}
    }
    return test_map;
}

void print_test_list() {
    auto tests = scan_attack_configs();
    if (tests.empty()) {cout << "In program are not any tests (folder empty or missing)" << endl; return;}
    for (const auto& [name, path] : tests) {cout << "Test: " << name << " -> " << path << endl;}
}

string RunStatus::findConfigByTestName(const string &name){
    auto tests = scan_attack_configs();
    if (tests.contains(name)) {return tests[name];}
    throw config_error("Unknown test name: %s", name.c_str());
}


bool parse_arguments(argparse::ArgumentParser & program, const int argc, char *argv[]){
    program.add_argument("--test")
          .help("Find name by test") // TODO add ---test_list to show
          .metavar("NAME");

    program.add_argument("--test_list")
           .help("List all named lists")
            .implicit_value(true)
            .default_value(false);

    program.add_argument("--config")
            .help("Path to config file of test run")
            .metavar("PATH");

    program.add_argument("--only_stats")
            .help("Run only statistics for an already finished test (no setup/attack)")
            .default_value(false)
            .implicit_value(true);

    try{
        program.parse_args(argc, argv);
    } catch(const runtime_error &err){
        throw config_error(err.what());
    }

    if(program.get<bool>("--test_list")){
        print_test_list();
        return false;
    }

    if(!program.present("--test") && !program.present("--config")){
        throw config_error("--test <test_name> or --config <path> is required");
    }
    return true;
}

int main(const int argc, char *argv[])  {

    argparse::ArgumentParser program("WPA3_tester", "1.0");
    if(!parse_arguments(program, argc, argv)){return 0;}

    RunStatus runStatus(program);
    globalRunStatus = &runStatus;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    runStatus.config_validation();

    const path base = current_path();
    const path data_root = base / "data" / "wpa3_test" / runStatus.config["name"];
    const path last_run = data_root / "last_run";

    // Ensure parent directories exist
    error_code ec;
    create_directories(data_root, ec);
    if (ec) {
        cerr << "CRITICAL ERROR: " << last_run.string() << " Error: " << ec.message() << endl;
        log(LogLevel::ERROR, "Failed to create run base directory: %s: %s", data_root.string().c_str(), ec.message().c_str());
        throw runtime_error("Unable to create run base directory");
    }
    runStatus.run_folder = last_run.string(); //TODO should be changeable with argument

    if(runStatus.only_stats){
        runStatus.stats_test();
        return 0;
    }

    runStatus.config_requirement(); //include req validation
    runStatus.setup_test();

    //debug_step();

    runStatus.run_test();
    //TODO removeall processes?
    runStatus.stats_test();

    return 0;
}
