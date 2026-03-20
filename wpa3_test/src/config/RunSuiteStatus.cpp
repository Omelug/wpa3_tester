#include "config/RunSuiteStatus.h"

#include <string>
#include <nlohmann/json-schema.hpp>
#include <nlohmann/json.hpp>

#include "config/Actor_config.h"
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
        log(LogLevel::INFO, "Used test suite config "+this->config_path);
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
            auto test_config_path = gen_folder / (to_string(i)+"_test.yaml");

            auto tmp_path = path(test_config_path.string() +".tmp.yaml");
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
                throw runtime_error("Unresolved "+var_PREFIX+" placeholders at index "+to_string(i));
            }

            remove(tmp_path);
            ofstream ofs(test_config_path);
            if (!ofs.is_open()) { throw runtime_error("Could not open final config file for writing"); }
            ofs << config_str;
            ofs.close();

            RunStatus::config_validation(test_config_path);
            test_map.emplace_back(to_string(i) +"_test", test_config_path);
        }
    }

    map<string, size_t> analyze_template_vars(const string& config_template) {
        map<string, set<size_t>> found_indices;
        const regex var_regex(var_PREFIX +"([a-zA-Z0-9]+)_([0-9]+)");
        smatch match;

        // scan config for used vars
        auto search_start(config_template.cbegin());
        while (regex_search(search_start, config_template.cend(), match, var_regex)) {
            found_indices[match[1]].insert(stoul(match[2]));
            search_start = match.suffix().first;
        }

        // 0... N , save count
        map<string, size_t> required_counts;
        for (auto& [name, indices] : found_indices) {
            const size_t max_idx = *indices.rbegin();
            if (indices.size() != max_idx + 1) {
                throw setup_err("Variable '"+name+"' has gaps in indexing, expected sequence from 0 to "+to_string(max_idx));
            }
            required_counts[name] = indices.size();
        }

        return required_counts;
    }

    vector<pair<string, vector<vector<string>>>> prepare_variable_groups(
        const json& vars_node,const map<string, size_t>& required_counts){
        vector<pair<string, vector<vector<string>>>> groups;

        for (auto const& [name, count] : required_counts) {
            if (!vars_node.contains(name)) {
                throw runtime_error("Variable '"+name +"' missing in 'vars' definition.");
            }

            auto elements = vars_node.at(name).get<vector<string>>();
            if (count > elements.size()) {
                throw runtime_error("Variable '"+name +"' needs "+to_string(count) +" values.");
            }

            // variations for one group
            ranges::sort(elements);
            vector<vector<string>> variations;

            do { // generate all permutations + deduplication
                vector current_var(elements.begin(), next(elements.begin(), static_cast<std::ptrdiff_t>(count)));
                if (ranges::find(variations, current_var) == variations.end()) {
                    variations.push_back(current_var);
                }
            } while (ranges::next_permutation(elements).found);

            groups.emplace_back(name, variations);
        }

        return groups;
    }

    void RunSuiteStatus::generate_test_files(
        basic_json<> source_info,
        const vector<pair<string, vector<vector<string>>>>& groups,
        const path& gen_folder,
        config_paths& test_map)
    {
        path tmp_template = gen_folder / "template_base.tmp.yaml";
        save_yaml(source_info.at("config"), tmp_template);

        ifstream ifs(tmp_template);
        if (!ifs.is_open()) { throw runtime_error("Could not open template file for reading"); }
        string raw_yaml_template((istreambuf_iterator(ifs)), istreambuf_iterator<char>());
        ifs.close();

        vector<size_t> indices(groups.size(), 0);
        bool done = false;
        size_t test_counter = 0;


        while (!done){
            string current_config_str = raw_yaml_template;
            for (size_t g = 0; g < groups.size(); ++g) {
                const string& var_name = groups[g].first;
                const vector<string>& current_variation = groups[g].second[indices[g]];

                for (size_t i = 0; i < current_variation.size(); ++i) {
                    string placeholder = var_PREFIX + var_name +"_"+to_string(i);
                    replace_all(current_config_str, placeholder, current_variation[i]);
                }
            }

            if (current_config_str.find(var_PREFIX) != string::npos) {
                throw runtime_error("Unresolved "+var_PREFIX +" placeholders in test "+to_string(test_counter));
            }

            string test_id = to_string(test_counter);
            path test_path = gen_folder / (test_id +"_test.yaml");

            // save result to file
            ofstream ofs(test_path);
            if (!ofs.is_open()) { throw runtime_error("Could not open final config file for writing"); }
            ofs << current_config_str;
            ofs.close();

            // result test config validation
            RunStatus::config_validation(test_path);
            test_map.emplace_back(test_id +"_test", test_path);

            // another index or stop
            test_counter++;
            for (size_t i = groups.size(); i-- > 0; ) {
                if (++indices[i] < groups[i].second.size()) { break; }
                if (i == 0) { done = true; }
                else { indices[i] = 0; }
            }
        }
        remove(tmp_template);
    }

    void RunSuiteStatus::defined_by_permutation(basic_json<> source_info, const string &source_name, const path &test_config_folder, config_paths &test_map){
        auto gen_folder = test_config_folder / source_name;
        create_directories(gen_folder);

        const auto vars_node = source_info.at("vars");
        const string config_template = source_info.at("config").dump();

        const auto required_counts = analyze_template_vars(config_template);

        // vector of (var_name, vector of var variations)
        const auto groups = prepare_variable_groups(vars_node, required_counts);
        generate_test_files(source_info, groups, gen_folder, test_map);
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
            if (type == "permutation"){
                defined_by_permutation(source_info, source_name, test_config_folder, test_map);
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
