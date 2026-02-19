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

    json RunSuiteStatus::config_validation(const string &configPath){
        try {
            YNode config_node = YAML::LoadFile(configPath);
            nlohmann::json config_json = yaml_to_json(config_node);

            // create base config node
            config_json = RunStatus::extends_recursive(config_json, configPath);

            //part validation
            RunStatus::validate_recursive(config_json, path(configPath).parent_path());

            //global validation
            path global_schema_path = path(PROJECT_ROOT_DIR)/"attack_config"/"validator"/"test_suite_validator.yaml";
            nlohmann::json_schema::json_validator global_validator;
            global_validator.set_root_schema(yaml_to_json(
                YAML::LoadFile(global_schema_path.string())
            ));
            global_validator.validate(config_json);

            return config_json;

        } catch (const domain_error &e) {
            throw config_error(string("Schema error: ") + e.what());
        } catch (const invalid_argument &e) {
            throw config_error(string("Error in config: ") + e.what());
        } catch (const exception& e) {
            throw config_error(string("Config validation error: ") + e.what());
        }
    }

    void replace_all(std::string& str, const std::string& from, const std::string& to) {
        if(from.empty()) return;
        size_t start_pos = 0;
        while((start_pos = str.find(from, start_pos)) != std::string::npos) {
            str.replace(start_pos, from.length(), to);
            start_pos += to.length();
        }
    }

    vector<pair<string, path>> RunSuiteStatus::get_test_paths(){
        const auto test_config_folder = path(this->run_folder) / "test_config";

        //create folder
        error_code ec;
        create_directories(test_config_folder, ec);
        if (ec) {throw runtime_error("Unable to create directory");}

        std::vector<pair<std::string, path>> test_map;
        for (auto& [source_name, source_info] : config.at("tests").items()) {
            std::string type = source_info.at("type");
            if (type == "path") {
                path rel_path = source_info.at("path").get<std::string>();
                path abs_path = absolute(configPath / rel_path);
                test_map.emplace_back(source_name, abs_path);
            }else if (type == "generator") {
                auto source_config = source_info.at("config");
                auto gen_folder = test_config_folder / source_name;
                //create folder
                create_directories(test_config_folder, ec);
                if (ec) {throw runtime_error("Unable to create generator directory");}

                // check len are same
                auto vars = source_info.at("vars");
                size_t length = 0; bool first = true;
                for (auto& [key, value] : vars.items()) {
                    if (first) {
                        length = value.size(); first = false;
                    } else if (value.size() != length) {
                        throw config_error("All vars lists must have the same length (error in '" + key + "')");
                    }
                }

                auto source_config_raw = source_info.at("config").dump();
                for (size_t i = 0; i < length; ++i) {
                    string current_config = source_config_raw;

                    // replace vars
                    for (auto& [key, value] : vars.items()) {
                       string placeholder = "var_" + key;
                       string replacement;

                        // strings/ arrays
                        if (value[i].is_string()) replacement = value[i].get<std::string>();
                        else replacement = value[i].dump();

                        replace_all(current_config, placeholder, replacement);
                    }
                    if (current_config.find("var_") !=string::npos) {
                        throw config_error("Unresolved var_ placeholders at index " + to_string(i));
                    }

                    json final_json = RunStatus::config_validation(json::parse(current_config));
                    string test_name = final_json.at("name");
                    string filename = std::to_string(i) + "_" + test_name + ".yaml";
                    std::ofstream out(gen_folder / filename);
                    out << final_json.dump();
                    test_map.emplace_back(std::to_string(i) + "_" + test_name, gen_folder / filename);
                }
            }
        }
        return test_map;
    }


    void RunSuiteStatus::execute(){
        this->config = config_validation(this->configPath);
        auto tests_paths = get_test_paths();
        // run tests
        for (const auto& [name, test_path] : tests_paths) {
            RunStatus rs(test_path);
            path suite_name = rs.config.at("name").get<std::string>();
            rs.run_folder = path(this->run_folder) / suite_name / "last_run" / name;

            // TODO co s test_report, compile_external, install_requerements ?

           string rewrite_mode;
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
    }

    string RunSuiteStatus::findConfigByTestSuiteName(const string &name){
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
