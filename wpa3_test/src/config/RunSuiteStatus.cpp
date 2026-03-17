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
    using namespace nlohmann;
    using YNode = YAML::Node;

    RunSuiteStatus::RunSuiteStatus(const string &config_path, string suite_name){
        this->config_path = config_path;
        if(!exists(config_path)){throw config_err("Config not found: "+config_path);}

        if(suite_name.empty()){
            const YNode node = YAML::LoadFile(config_path);
            if(!node["name"] || !node["name"].IsScalar())
                throw config_err("Config missing required string field 'name': "+config_path);
            suite_name = node["name"].as<string>();
        }

        run_folder = (BASE_FOLDER / suite_name / "last_run").string();
        log(LogLevel::INFO, "Used test suite config "+ this->config_path);
        this->config = config_validation(this->config_path);
    }

    json RunSuiteStatus::config_validation(const string &config_path){
        try {
            const YNode config_node = YAML::LoadFile(config_path);
            json config_json = yaml_to_json(config_node);

            config_json = RunStatus::extends_recursive(config_json, config_path);
            RunStatus::validate_recursive(config_json, path(config_path).parent_path());

            //global validation
            const path global_schema_path = path(PROJECT_ROOT_DIR)/"attack_config"/"validator"/"test_suite_validator.schema.yaml";
            json_schema::json_validator global_validator;
            global_validator.set_root_schema(yaml_to_json(
                YAML::LoadFile(global_schema_path.string())
            ));
            global_validator.validate(config_json);

            return config_json;

        } catch (const domain_error &e) {
            throw config_err(string("Schema error: ") + e.what());
        } catch (const invalid_argument &e) {
            throw config_err(string("Error in config: ") + e.what());
        } catch (const exception& e) {
            throw config_err(string("Config validation error: ") + e.what());
        }
    }

    void RunSuiteStatus::defined_by_path(basic_json<> source_j, const string &source_name, config_paths &test_map) const{
        const path rel_path = source_j.at("path").get<string>();
        path abs_path = absolute(path(config_path).parent_path() / rel_path);
        test_map.emplace_back(source_name, abs_path);
    }

    void replace_all(string& str, const string& from, const string& to) {
        if(from.empty()) return;
        size_t start_pos = 0;
        while((start_pos = str.find(from, start_pos)) != string::npos) {
            str.replace(start_pos, from.length(), to);
            start_pos += to.length();
        }
    }

    void RunSuiteStatus::defined_by_generator(basic_json<> source_info, const string &source_name, const path &test_config_folder, config_paths &test_map){
        auto source_config = source_info.at("config");
        auto gen_folder = test_config_folder / source_name;

        error_code ec;
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
                const string json_placeholder = var_PREFIX + key;
                auto replacement = value[i].get<string>();
                replace_all(config_str, json_placeholder, replacement);
            }

            // unresolved var_
            if (config_str.find(var_PREFIX) != string::npos) {
                remove(tmp_path);
                throw runtime_error("Unresolved "+var_PREFIX+" placeholders at index " + to_string(i));
            }

            remove(tmp_path);
            ofstream ofs(test_config_path);
            if (!ofs.is_open()) { throw runtime_error("Could not open final config file for writing"); }
            ofs << config_str;
            ofs.close();

            RunStatus::config_validation(test_config_path);
            test_map.emplace_back(to_string(i) + "_test", test_config_path);
        }
    }

    config_paths RunSuiteStatus::get_test_paths(){
        const auto test_config_folder = path(this->run_folder) / "test_config";

        error_code ec; //create test folder
        create_directories(test_config_folder, ec);
        if (ec) {throw runtime_error("Unable to create directory");}

        config_paths test_map;
        for (auto& [source_name, source_info] : config.at("tests").items()) {
            const string & type = source_info.at("type");
            if (type == "path"){
                defined_by_path(source_info, source_name, test_map);
                continue;
            }
            if (type == "generator"){
                defined_by_generator(source_info, source_name, test_config_folder, test_map);
                continue;
            }
            throw config_err("invalid source type");
        }

        // test_suite level overrides to all test configs at the end
        json suite_overrides = json::object();
        if (config.contains("test_report")) {suite_overrides["test_report"] = config["test_report"];}
        if (config.contains("compile_external")) {suite_overrides["compile_external"] = config["compile_external"];}
        if (config.contains("install_req")) {suite_overrides["install_req"] = config["install_req"];}
        if (!suite_overrides.empty()) {
            for (auto &test_path: test_map | views::values) {
                json test_config = yaml_to_json(YAML::LoadFile(test_path.string()));
                for (auto& [key, value] : suite_overrides.items()) {
                    test_config[key] = value;
                }
                save_yaml(test_config, test_path);
            }
        }

        return test_map;
    }


    void RunSuiteStatus::execute(){
        auto tests_paths = get_test_paths();
        // run tests
        for (const auto& [name, test_path] : tests_paths) {
            RunStatus rs(test_path, name, ".");
            rs.only_stats = this->only_stats;
            path suite_name = rs.config.at("name").get<string>();
            rs.run_folder = path(this->run_folder) / suite_name / "last_run" / name;

            string rewrite_mode = "false";
            if (config.contains("rewrite") && config.at("rewrite").is_string()) {
                rewrite_mode = config.at("rewrite").get<string>();
            }

            if (exists(rs.run_folder)) {
                if (rewrite_mode == "false") {
                    log(LogLevel::DEBUG, "Skipping: "+name);
                    continue;
                }

                if (config.at("rewrite") == "errors" && !exists(path(rs.run_folder) / "errors.txt")) {
                    log(LogLevel::WARNING, "Skipping successful test : "+name);
                    continue;
                }

                if (config.value("delete_old", false)){
                    log(LogLevel::DEBUG, "Deleting old run folder: "+name);
                    remove_all(rs.run_folder);
                }
            }
            rs.execute();
        }
    }

    string RunSuiteStatus::findConfigByTestSuiteName(const string &name){
        auto tests = RunStatus::scan_attack_configs(TEST_SUITE);
        if (tests.contains(name)) {return tests[name];}
        throw config_err("Unknown test suite name: "+name);
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
    size_t RunSuiteStatus::check_vars_len_same(basic_json<> source_info){
        // check len are same
        auto vars = source_info.at("vars");
        size_t length = 0; bool first = true;
        for (auto& [key, value] : vars.items()) {
            if (first) {
                length = value.size(); first = false;
            } else if (value.size() != length) {
                throw config_err("All vars lists must have the same length (error in '"+key+"')");
            }
        }
        return length;
    }

}
