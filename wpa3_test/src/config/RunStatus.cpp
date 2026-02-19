#include "config/RunStatus.h"
#include <csignal>
#include <filesystem>
#include "logger/error_log.h"
#include "logger/log.h"
#include <argparse/argparse.hpp>
#include <string>
#include <yaml-cpp/yaml.h>
#include "attacks/attacks.h"
#include "setup/config_parser.h"

namespace wpa3_tester{
    using namespace std;
    using namespace filesystem;

    RunStatus::RunStatus(const std::string &configPath){
        this->configPath = configPath;
        if(!exists(configPath)){throw config_error("Config not found: %s", configPath.c_str());}
        log(LogLevel::INFO, "Used config %s", this->configPath.c_str());
    }

    void RunStatus::execute(){

       //TODO  globalRunStatus = &runStatus;

        this->config = config_validation(this->configPath);

        // Ensure parent directories exist

        error_code ec;
        create_directories(run_folder, ec);
        if (ec) {throw runtime_error("Unable to create run base directory");}

        config_requirement(); //include req validation
        setup_test();
        run_test();
        //TODO removeall processes?
        stats_test();
    };


    void RunStatus::run_test(){
        attack_module_maps::run_map[config["attacker_module"]](*this);
        //TODO teardown , reset interfaces
    }

    void RunStatus::stats_test(){
        attack_module_maps::stats_map[config["attacker_module"]](*this);
    }

    void RunStatus::save_actor_interface_mapping(){

        // mapping of actors -> iface to run_folder/mapping.txt
        if (run_folder.empty()) {
            log(LogLevel::WARNING, "save_actor_interface_mapping: run_folder not set");
            return;
        }

        const string path = run_folder + "/mapping.txt";
        ofstream ofs(path, ios::out | ios::trunc);
        if (!ofs) {
            log(LogLevel::ERROR, "Failed to open %s for writing actor/interface mapping", path.c_str());
            return;
        }

        ofs << "Actor->interface mapping" << endl;
        ofs << "Internal mapping" << endl;
        log_actor_configs(internal_actors, ofs);

        ofs << "External mapping" << endl;
        log_actor_configs(external_actors, ofs);

        ofs << "Simulation mapping" << endl;
        log_actor_configs(simulation_actors, ofs);

        ofs.close();
        log(LogLevel::INFO, "Actor/interface mapping written to %s", path.c_str());
    };

    Actor_config& RunStatus::get_actor(const string& actor_name){
        Actor_config* found = nullptr;

        auto check_map = [&](ActorCMap& m, const char* map_name) {
            if (const auto it = m.find(actor_name); it != m.end()) {
                if (found != nullptr) {
                    throw config_error("Actor %s found in multiple maps (including %s)",actor_name.c_str(), map_name);
                }
                found = it->second.get();
            }
        };

        check_map(external_actors, "external_actors");
        check_map(internal_actors, "internal_actors");
        check_map(simulation_actors, "simulation_actors");

        if (!found) {throw config_error("Actor %s not found in any actor map", actor_name.c_str());}
        return *found;
    }

    unordered_map<string, string> RunStatus::scan_attack_configs(const CONFIG_TYPE ct) {
        unordered_map<string, string> t_map;
        const path attack_config_dir = path(PROJECT_ROOT_DIR)/ "attack_config";

        if (!exists(attack_config_dir) || !is_directory(attack_config_dir)) {return t_map;}

        for (const auto& entry : recursive_directory_iterator(attack_config_dir)) {
            const auto& path = entry.path();
            string filename = path.filename().string();
            if (filename.ends_with(".schema.yaml") || path.extension() != ".yaml") {continue;}

            try {
                YAML::Node config = YAML::LoadFile(path.string());
                nlohmann::json config_json = yaml_to_json(config);
                if(!config_json.contains("name")){ throw config_error("Path %s has no valid name", path.string().c_str()); }
                auto name = config["name"].as<string>();
                if(config_json.contains("config_type") && config_json["config_type"] == "test_suite"
                    && ct == TEST_SUITE){
                    t_map[name] = path.string();
                }else if(ct == TEST){
                    t_map[name] = path.string();
                    if (t_map.contains(name)) {
                        throw config_error("Configs " + t_map[name] +
                            " and " + path.string() + " have same name!");
                    }
                }
            } catch (const YAML::Exception& e) {throw config_error("Invalid yaml {}", e.what());}
        }
        return t_map;
    }

    string RunStatus::findConfigByTestName(const string &name){
        auto tests = scan_attack_configs();
        if (tests.contains(name)) {return tests[name];}
        throw config_error("Unknown test name: %s", name.c_str());
    }

    void RunStatus::print_test_list() {
        auto tests = scan_attack_configs(TEST);
        if (tests.empty()) {cout << "In program are not any tests" << endl; return;}
        for (const auto& [name, path] : tests) {cout << "Test: " << name << " -> " << path << endl;}
    }
}
