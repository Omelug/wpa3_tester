#include "config/RunStatus.h"
#include <filesystem>
#include <chrono>
#include <iomanip>
#include <sstream>
#include "logger/error_log.h"
#include "logger/log.h"
#include <string>
#include <yaml-cpp/yaml.h>
#include "attacks/attacks.h"
#include "ex_program/external_actors/openwrt/OpenWrtConn.h"
#include "setup/config_parser.h"

namespace wpa3_tester{
    using namespace std;
    using namespace filesystem;

    static string current_time_string() {
        const auto now = chrono::system_clock::now();
        const auto timer = chrono::system_clock::to_time_t(now);
        tm bt{};
        localtime_r(&timer, &bt);

        ostringstream oss;
        oss << put_time(&bt, "%Y-%m-%d %H:%M:%S");
        return oss.str();
    }

    RunStatus::RunStatus(const std::string &config_path, string testName){
        this->config_path = config_path;
        if(!exists(config_path)){throw config_error("Config not found: %s", config_path.c_str());}

        if(testName.empty()){
            // load name from YAML if not name set
            const YAML::Node node = YAML::LoadFile(config_path);
            if (!node["name"] || !node["name"].IsScalar()){
                throw config_error("Config missing required string field 'name': %s", config_path.c_str());
            }
            testName = node["name"].as<string>();
        }

        run_folder = (BASE_FOLDER / testName / "last_run").string();
        log(LogLevel::INFO, "Used config %s", this->config_path.c_str());
        this->config = config_validation(this->config_path);
    }

    void RunStatus::execute(){

        globalRunStatus = this;

        // Ensure parent directories exist
        error_code ec;
        create_directories(run_folder, ec);
        if (ec) {throw runtime_error("Unable to create run base directory");}

        //try { //TODO cleanup
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
                error_log << endl;
                error_log.close();
                log(LogLevel::ERROR, "Error written to %s", error_file.string().c_str());
            } else {
                log(LogLevel::ERROR, "Failed to open error log file: %s", error_file.string().c_str());
            }
            //FIXME clean up
            throw;
        }*/
    }

    void RunStatus::get_or_create_connection(const ActorPtr& actor) const{
        ExternalConn* conn_raw = nullptr;
        if(actor["external_OS"] == "openwrt"){
            conn_raw = new OpenWrtConn();
        }else{
          throw not_implemented_error("Not known external_OS: " + actor["external_OS"]);
        }

        const shared_ptr<ExternalConn> conn(conn_raw);
        if (!conn->connect(*this, actor)) {throw config_error("Failed to connect to external actor ");}
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
        } else {log(LogLevel::DEBUG, "run function not set");}

    }

    void write_actors_csv(const ActorCMap& actors, ofstream& ofs){
        for (const auto& [name, actor] : actors) {
            ofs << actor->str_con.at("source").value_or("<none>") << ","
                << name << ","
                << actor->str_con.at("iface").value_or("<none>") << ","
                << actor->str_con.at("mac").value_or("<none>") << ","
                << actor->str_con.at("driver").value_or("<none>") << endl;
        }
    }

    void RunStatus::save_actor_interface_mapping() const {
        if (run_folder.empty()) {
            log(LogLevel::WARNING, "save_actor_interface_mapping: run_folder not set");
            return;
        }

        const string path = run_folder + "/mapping.csv";
        ofstream ofs(path, ios::out | ios::trunc);
        if (!ofs) {
            log(LogLevel::ERROR, "Failed to open %s for writing CSV mapping", path.c_str());
            return;
        }

        ofs << "Type,ActorName,Interface,MAC,Driver" << endl;

        write_actors_csv(actors, ofs);

        ofs.close();
        log(LogLevel::INFO, "Actor/interface mapping written to CSV: %s", path.c_str());
    }

    //TODO only gtter now,
    ActorPtr &RunStatus::get_actor(const string &actor_name){
        if (const auto it = actors.find(actor_name); it != actors.end()){return it->second;}
        throw config_error("Actor %s not found in any actor map", actor_name.c_str());
    }

    unordered_map<string, string> RunStatus::scan_attack_configs(const CONFIG_TYPE ct) {
        unordered_map<string, string> t_map;
        const path attack_config_dir = path(PROJECT_ROOT_DIR)/ "attack_config";

        if (!exists(attack_config_dir) || !is_directory(attack_config_dir)) {return t_map;}

        for (const auto& entry : recursive_directory_iterator(attack_config_dir)) {
            const auto& path = entry.path();
            string filename = path.filename().string();
            if (filename == "global_config.yaml" || filename.ends_with(".schema.yaml") || path.extension() != ".yaml") {continue;}
            try {
                YAML::Node config = YAML::LoadFile(path.string());
                nlohmann::json config_json = yaml_to_json(config);
                if(!config_json.contains("name")){ throw config_error("Path %s has no valid name", path.string().c_str()); }
                auto name = config["name"].as<string>();
                if(config_json.contains("config_type") && config_json.at("config_type") == "test_suite"
                    && ct == TEST_SUITE){
                    t_map[name] = path.string();
                }else if(ct == TEST && (!config_json.contains("config_type") || config_json.at("config_type") == "test")){
                    if (t_map.contains(name)) {
                        throw config_error("Configs " + t_map[name] +
                            " and " + path.string() + " have same name!");
                    }
                    t_map[name] = path.string();
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
