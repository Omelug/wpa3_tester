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

    RunSuiteStatus::RunSuiteStatus(const string &config_path, string suite_name){
        this->config_path = config_path;
        if(!exists(config_path)){throw config_error("Config not found: %s", config_path.c_str());}

        if(suite_name.empty()){
            const YNode node = YAML::LoadFile(config_path);
            if(!node["name"] || !node["name"].IsScalar())
                throw config_error("Config missing required string field 'name': %s", config_path.c_str());
            suite_name = node["name"].as<string>();
        }

        run_folder = (BASE_FOLDER / suite_name / "last_run").string();
        log(LogLevel::INFO, "Used test suite config %s", this->config_path.c_str());
        this->config = config_validation(this->config_path);
    }

    json RunSuiteStatus::config_validation(const string &config_path){
        try {
            const YNode config_node = YAML::LoadFile(config_path);
            nlohmann::json config_json = yaml_to_json(config_node);

            config_json = RunStatus::extends_recursive(config_json, config_path);
            RunStatus::validate_recursive(config_json, path(config_path).parent_path());

            //global validation
            const path global_schema_path = path(PROJECT_ROOT_DIR)/"attack_config"/"validator"/"test_suite_validator.schema.yaml";
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
    void replace_all(string& str, const string& from, const string& to) {
        if(from.empty()) return;
        size_t start_pos = 0;
        while((start_pos = str.find(from, start_pos)) != string::npos) {
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

        vector<pair<string, path>> test_map;
        for (auto& [source_name, source_info] : config.at("tests").items()) {
            string type = source_info.at("type");
            if (type == "path") {
                path rel_path = source_info.at("path").get<string>();
                path abs_path = absolute(path(config_path).parent_path() / rel_path);
                test_map.emplace_back(source_name, abs_path);
            } else if (type == "generator") {
                auto source_config = source_info.at("config");
                auto gen_folder = test_config_folder / source_name;

                create_directories(gen_folder, ec);
                if (ec) { throw runtime_error("Unable to create generator directory"); }

                auto length = check_vars_len_same(source_info);
                auto vars = source_info.at("vars");

                for (size_t i = 0; i < length; ++i) {
                    auto test_config_path = (gen_folder / (to_string(i) + "_test.yaml"));
                    
                    auto tmp_path = path(test_config_path.string() + ".tmp.yaml");
                    save_yaml(source_info.at("config"), tmp_path);

                    ifstream ifs(tmp_path);
                    if (!ifs.is_open()) { throw runtime_error("Could not open temp file for reading"); }
                    string config_str((istreambuf_iterator(ifs)), istreambuf_iterator<char>());
                    ifs.close();
                    
                    for (auto& [key, value] : vars.items()) {
                        const string json_placeholder = "var_" + key;
                        auto replacement = value[i].get<string>();
                        replace_all(config_str, json_placeholder, replacement);
                    }

                    if (config_str.find("var_") != string::npos) {
                        filesystem::remove(tmp_path);
                        throw runtime_error("Unresolved var_ placeholders at index " + to_string(i));
                    }

                    filesystem::remove(tmp_path);

                    ofstream ofs(test_config_path);
                    if (!ofs.is_open()) { throw runtime_error("Could not open final config file for writing"); }
                    ofs << config_str;
                    ofs.close();

                    RunStatus::config_validation(test_config_path);
                    test_map.emplace_back(to_string(i) + "_test", test_config_path);
                }
            }
        }
        return test_map;
    }


    void RunSuiteStatus::execute(){
        auto tests_paths = get_test_paths();
        // run tests
        for (const auto& [name, test_path] : tests_paths) {
            RunStatus rs(test_path);
            rs.only_stats = this->only_stats;
            path suite_name = rs.config.at("name").get<string>();
            rs.run_folder = path(this->run_folder) / suite_name / "last_run" / name;

            // TODO co s test_report, compile_external, install_requerements ?

           string rewrite_mode = "false";
            if (config.contains("rewrite") && config.at("rewrite").is_string()) {
                rewrite_mode = config.at("rewrite").get<string>();
            }

            if (exists(rs.run_folder)) {
                if (rewrite_mode == "false") {
                    log(LogLevel::DEBUG, "Skipping: %s", name.c_str());
                    continue;
                }

                if (config.at("rewrite") == "errors" && !exists(path(rs.run_folder) / "errors.txt")) {
                    log(LogLevel::WARNING, "Skipping successful test : %s", name.c_str());
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
    }

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

    // help config validation functions
    size_t RunSuiteStatus::check_vars_len_same(nlohmann::basic_json<> source_info){
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
        return length;
    }

}
