#include "config/RunStatus.h"
#include <filesystem>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <optional>
#include "logger/error_log.h"
#include "logger/log.h"
#include <string>
#include <yaml-cpp/yaml.h>
#include "attacks/attacks.h"
#include "config/Observer_config.h"
#include "ex_program/external_actors/openwrt/OpenWrtConn.h"
#include "setup/config_parser.h"

namespace wpa3_tester{
    using namespace std;
    using namespace filesystem;

     string current_time_string() {
        const auto now = chrono::system_clock::now();
        const auto timer = chrono::system_clock::to_time_t(now);
        tm bt{};
        localtime_r(&timer, &bt);

        ostringstream oss;
        oss << put_time(&bt, "%Y-%m-%d %H:%M:%S");
        return oss.str();
    }

    string relative_from(const string& base_dir_name, const string& config_path) {
        const path config_full_path = absolute(config_path);
        const path config_dir = config_full_path.parent_path();

        path current = config_dir;
        string relative_path;

         while (current != current.parent_path()) {
             if (current.filename() == base_dir_name) {
                 return relative_path.empty() ? "." : relative_path;
             }
             if (!relative_path.empty()) {
                 relative_path = current.filename().string().append("/").append(relative_path);
             } else {
                 relative_path = current.filename().string();
             }
             current = current.parent_path();
         }

        if (!current.empty() && current.filename() == base_dir_name) {
            return relative_path.empty() ? "." : relative_path;
        }
        throw config_err("folder name not found");
    }

    RunStatus::RunStatus(const string &config_path, string testName, const string &sub_folder){
        this->config_path = config_path;
        if(!exists(config_path)){throw config_err("Config not found: "+config_path);}

        if(testName.empty()){
            // load name from YAML if not name set
            const YAML::Node node = YAML::LoadFile(config_path);
            if (!node["name"] || !node["name"].IsScalar()){
                throw config_err("Config missing required string field 'name':"+config_path);
            }
            testName = node["name"].as<string>();
        }
        // add subfolder from test default
        string actual_sub_folder = ".";
        if (sub_folder.empty()) {
            actual_sub_folder = relative_from("attack_config", this->config_path);
        }
        run_folder = (BASE_FOLDER / actual_sub_folder / testName / "last_run").string();
        log(LogLevel::INFO, "Used config "+this->config_path);
        this->config = config_validation(this->config_path);
    }

    void RunStatus::clean(){
         this->process_manager.stop_all();
         this->actors.clear();
         this->observers.clear();
     };

    void print_exception_tree(const exception& e, ostream& os, int level = 0) {
        os << string(level * 2, ' ') << "- " << e.what() << endl;
        try {
            rethrow_if_nested(e);
        } catch (const exception& nested) {
            print_exception_tree(nested, os, level + 1);
        } catch (...) {}
    }

    void RunStatus::execute(){

        globalRunStatus = this;

        // Ensure parent directories exist
        error_code ec;
        create_directories(run_folder, ec);
        if (ec) {throw runtime_error("Unable to create run base directory");}

        //try {
            if(this->only_stats){stats_test(); return;}

            config_requirement(); //include req validation
            setup_test();
            const path out_path = path(run_folder) / "test_config.yaml";
            save_yaml(config, out_path);
            run_test();
            stats_test();
        /*} catch (const exception& e) {
            const path error_file = path(run_folder) / "errors.txt";
            ofstream error_log(error_file, ios::out | ios::app);
            if (error_log.is_open()) {
                error_log << "=== Error occurred at " << current_time_string() << " ===" << endl;
                error_log << "Exception type: " << typeid(e).name() << endl;
                error_log << "Message: " << e.what() << endl;
                print_exception_tree(e, error_log);
                error_log << endl;
                error_log.close();
                log(LogLevel::ERROR, "Error written to %s", error_file.string().c_str());
            } else {
                log(LogLevel::ERROR, "Failed to open error log file: %s", error_file.string().c_str());
            }
            log(LogLevel::INFO, "Cleaning up resources before exit...");
            clean();
        }*/
    }

    void RunStatus::get_or_create_connection(const ActorPtr& actor){
        if(actor->conn){return;}
         shared_ptr<ExternalConn> conn;
         if(actor["external_OS"] == "openwrt"){
             conn = make_shared<OpenWrtConn>();
         } else {
             throw not_implemented_err("Not known external_OS: " + actor["external_OS"]);
         }

         if (!conn->connect(actor)) {
             throw config_err("Failed to connect to external actor");
         }
         actor->conn = conn;
     }

    void RunStatus::run_test(){
        process_manager.write_log_all("@START");
        const auto module_name = config.at("attacker_module");
        const auto run_it = attack_module_maps::run_map.find(module_name);

        if (run_it != attack_module_maps::run_map.end()) {run_it->second(*this);
        } else {log(LogLevel::DEBUG, "run function not set");}

        process_manager.write_log_all("@END");
        process_manager.stop_all();
    }

    void RunStatus::stats_test(){
        const auto module_name = config.at("attacker_module");
        const auto run_it = attack_module_maps::stats_map.find(module_name);

        if (run_it != attack_module_maps::stats_map.end()) {run_it->second(*this);
        } else { log(LogLevel::DEBUG, "run function not set"); }

    }

    void write_actors_csv(const ActorCMap& actors, ofstream& ofs){
        for (const auto& [name, actor] : actors) {
            ofs << actor->str_con.at("source").value_or("<none>") << ","
                << name << ","
                << actor->str_con.at("iface").value_or("<none>") << ","
                << actor->str_con.at("mac").value_or("<none>") << ","
                << actor->str_con.at("driver").value_or("<none>") << ","
                << actor->str_con.at("channel").value_or("<none>") << endl;
        }
    }

    void RunStatus::save_actor_interface_mapping() const {
        if (run_folder.empty()) {log(LogLevel::WARNING, "save_actor_interface_mapping: run_folder not set");return;}

        const string path = run_folder +"/mapping.csv";
        ofstream ofs(path, ios::out | ios::trunc);
        if (!ofs) {log(LogLevel::ERROR, "Failed to open "+path+" for writing CSV mapping");return;}

        ofs << "Type,ActorName,Interface,MAC,Driver,channel" << endl;

        write_actors_csv(actors, ofs);

        ofs.close();
        log(LogLevel::INFO, "Actor/interface mapping written to CSV: "+path);
    }

    ActorPtr &RunStatus::get_actor(const string &actor_name){
        if (const auto it = actors.find(actor_name); it != actors.end()){return it->second;}
        throw config_err("Actor "+actor_name+" not found in actors map");
    }

    unordered_map<string, string> RunStatus::scan_attack_configs(const CONFIG_TYPE ct) {
        unordered_map<string, string> t_map;
        const path attack_config_dir = path(PROJECT_ROOT_DIR)/ "attack_config";

        if (!exists(attack_config_dir) || !is_directory(attack_config_dir)) {return t_map;}

        for (const auto& entry : recursive_directory_iterator(attack_config_dir)) {
            const auto& path = entry.path();
            string filename = path.filename().string();
            if (filename == "global_config.yaml" || filename.ends_with(".schema.yaml") || path.extension() != ".yaml" || path.string().find("/validator/") != string::npos || path.string().find("/target/") != string::npos) {continue;}
            try {
                YAML::Node config = YAML::LoadFile(path.string());
                nlohmann::json config_json = yaml_to_json(config);
                if(!config_json.contains("name")){ throw config_err("Path "+path.string()+" has no valid name"); }
                auto name = config["name"].as<string>();
                if(config_json.contains("config_type") && config_json.at("config_type") == "test_suite"
                    && ct == TEST_SUITE){
                    t_map[name] = path.string();
                }else if(ct == TEST && (!config_json.contains("config_type") || config_json.at("config_type") == "test")){
                    if (t_map.contains(name)) {
                        throw config_err("Configs "+t_map[name]+" and "+path.string()+" have same name!");
                    }
                    t_map[name] = path.string();
                }
            } catch (const YAML::Exception& e) {throw config_err("Invalid yaml "+string(e.what()));}
        }
        return t_map;
    }

    string RunStatus::findConfigByTestName(const string &name){
        auto tests = scan_attack_configs();
        if (tests.contains(name)) {return tests[name];}
        throw config_err("Unknown test name: "+name);
    }

    void RunStatus::print_test_list() {
        auto tests = scan_attack_configs(TEST);
        if (tests.empty()) {cout << "In program are not any tests" << endl; return;}
        for (const auto& [name, path] : tests){
            cout << "Test: " << name << " -> " << path << endl;
        }
    }

    void RunStatus::start_observers(){
        for (const auto &observer: observers | views::values) {
            observer->start(*this);
        }
    }
}
