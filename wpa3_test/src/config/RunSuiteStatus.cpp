#include "config/RunSuiteStatus.h"

#include <string>
#include <nlohmann/json-schema.hpp>
#include <nlohmann/json.hpp>

#include "logger/error_log.h"
#include "setup/config_parser.h"
#include "system/ProcessManager.h"

namespace wpa3_tester{
    using namespace std;
    using namespace filesystem;
    using YNode = YAML::Node;
    using json = nlohmann::json;

    RunSuiteStatus::RunSuiteStatus(const std::string &configPath){
        this->configPath = configPath;
        if(!exists(configPath)){throw config_error("Config not found: %s", configPath.c_str());}
        log(LogLevel::INFO, "Used test suite config %s", this->configPath.c_str());
    }

    void RunSuiteStatus::config_validation(){
        try {
            YNode config_node = YAML::LoadFile(this->configPath);
            nlohmann::json config_json = yaml_to_json(config_node);

            // create base config node
            const path config_path(this->configPath);
            path config_dir = config_path.parent_path();
            vector<string> hierarchy;
            config_json = resolve_extends(config_json, config_dir, hierarchy);

            //part validation
            RunStatus::validate_recursive(config_json,config_dir);

            //global validation
            path global_schema_path = path(PROJECT_ROOT_DIR)/"attack_config"/"validator"/"test_suite_validator.yaml";
            string schema_str = global_schema_path.string();
            YNode global_schema_node = YAML::LoadFile(schema_str);
            nlohmann::json_schema::json_validator global_validator;
            global_validator.set_root_schema(yaml_to_json(global_schema_node));
            global_validator.validate(config_json);

            this->config = config_json;

        } catch (const domain_error &e) {
            throw config_error(string("Schema error: ") + e.what());
        } catch (const invalid_argument &e) {
            throw config_error(string("Error in config: ") + e.what());
        } catch (const exception& e) {
            throw config_error(string("Config validation error: ") + e.what());
        }
    }

    vector<pair<string, path>> RunSuiteStatus::get_test_paths(){
        const auto test_config_folder = path(this->run_folder) / "test_config";

        //create folder
        error_code ec;
        create_directories(test_config_folder, ec);
        if (ec) {throw runtime_error("Unable to create directory");}

        config_validation();

        std::vector<pair<std::string, path>> test_map;
        for (auto& [test_name, test_info] : config.at("tests").items()) {
            std::string type = test_info.at("type");
            if (type == "path") {
                path rel_path = test_info.at("path").get<std::string>();
                path abs_path = absolute(configPath / rel_path);
                test_map.emplace_back(test_name, abs_path);
            }
            else if (type == "generator") {
                //TODO  not implemented
                //std::cerr << "[Info] Test '" << test_name << "' uses generator (skipping).\n";
            }
        }
        return test_map;
    }


    void RunSuiteStatus::execute(){
        auto tests_paths = get_test_paths();
        for (const auto& [name, test_path] : tests_paths) {
            RunStatus rs(test_path);
            path suite_name = rs.config.at("name").get<std::string>();
            rs.run_folder = path(this->run_folder) / suite_name / "last_run" / name;

            // TODO co s test_report, compile_external, install_requerements ?

            std::string rewrite_mode;
            if (config["rewrite"].is_string()) {
                rewrite_mode = config["rewrite"].get<std::string>();
            } else if (config["rewrite"].is_boolean()) {
                rewrite_mode = "false";
            }

            if (exists(rs.run_folder)) {
                if (rewrite_mode == "all") {
                    log(LogLevel::DEBUG, "Skipping: %s", name.c_str());
                    continue;
                }

                if (config.at("rewrite") == "errors" && !exists(path(rs.run_folder) / "errors.txt")) {
                    log(LogLevel::WARNING, "Skipping test what cause error: %s", name.c_str());
                    continue;
                }

                if (config.value("delete_old", false)){
                    log(LogLevel::DEBUG, "Deleting old run folder: %s", name.c_str());
                    remove_all(rs.run_folder);
                }
            }

            rs.execute();
        }
        // run tests
    }

    string RunSuiteStatus::findConfigByTestSuiteName(const std::string &name){
        auto tests = RunStatus::scan_attack_configs(TEST_SUITE);
        if (tests.contains(name)) {return tests[name];}
        throw config_error("Unknown test suite name: %s", name.c_str());
    };

    void RunSuiteStatus::print_test_suite_list() {
        auto tests = RunStatus::scan_attack_configs(TEST_SUITE);
        if (tests.empty()) {cout << "In program are not any test suites" << endl; return;}
        for (const auto& [name, path] : tests) {cout << "Test-suite: " << name << " -> " << path << endl;}
    }

    void RunSuiteStatus::print_tests_in_suite(const string &ts_name){
        RunSuiteStatus rss(findConfigByTestSuiteName(ts_name));
        auto tests = rss.get_test_paths();
        if (tests.empty()) {cout << "Not tests in this suite" << endl; return;}
        for (const auto& [name, path] : tests) {cout << "Test: " << name << " -> " << path << endl;}
    }

}
