#include "config/RunStatus.h"
#include "logger/error_log.h"
#include <yaml-cpp/yaml.h>
#include <nlohmann/json.hpp>
#include <nlohmann/json-schema.hpp>
namespace wpa3_tester{
    using namespace std;
    using json = nlohmann::json;
    using YNode = YAML::Node;
    using namespace filesystem;

    json yaml_to_json(const YNode& node) {
        if (node.IsScalar()) {
            try { return node.as<bool>(); } catch (...) {}
            try { return node.as<int64_t>(); } catch (...) {}
            try { return node.as<double>(); } catch (...) {}
            return node.as<string>();
        }
        if (node.IsSequence()) {
            auto j = json::array();
            for (auto const& item : node) j.push_back(yaml_to_json(item));
            return j;
        }
        if (node.IsMap()) {
            auto j = json::object();
            for (auto it = node.begin(); it != node.end(); ++it) {
                j[it->first.as<string>()] = yaml_to_json(it->second);
            }
            return j;
        }
        return {};
    }

    void deep_merge(json& base, const json& patch) {
        for (auto it = patch.begin(); it != patch.end(); ++it) {
            if (it.value().is_object() && base.contains(it.key()) && base[it.key()].is_object()) {
                deep_merge(base[it.key()], it.value());
            } else {
                base[it.key()] = it.value();
            }
        }
    }

    json resolve_extends(json current_node, const path& base_dir, vector<string>& hierarchy) {
        if (!current_node.is_object()){
            return current_node;
        }
        if (current_node.contains("validator") && current_node["validator"].is_string()) {
            const path schema_rel_path = current_node["validator"].get<string>();
            const path schema_abs_path = absolute(base_dir / schema_rel_path);
            current_node["validator"] = schema_abs_path.string();
        }
        if(!current_node.contains("extends")){
            for (auto& [key, value] : current_node.items()) {
                value = resolve_extends(value, base_dir, hierarchy);
            }
            return current_node;
        }

        // extends
        const path parent_path = absolute(base_dir / current_node["extends"].get<string>());
        const string parent_path_str = parent_path.string();

        if (ranges::find(hierarchy, parent_path_str) != hierarchy.end()) {
            throw config_error("Circular inheritance detected! File already in hierarchy: " + parent_path_str);
        }

        hierarchy.push_back(parent_path_str);
        current_node.erase("extends");

        const YNode parent_yaml = YAML::LoadFile(parent_path.string());
        json parent_json = yaml_to_json(parent_yaml);
        deep_merge(parent_json, current_node);
        parent_json = resolve_extends(parent_json, parent_path.parent_path(), hierarchy);

        // remove from hierarchy
        hierarchy.pop_back();
        return parent_json;
    }

    json RunStatus::extends_recursive(const nlohmann::json& config_json, const string &configPath){
        const path config_path(configPath);
        path config_dir = config_path.parent_path();
        vector<string> hierarchy;
        return resolve_extends(config_json, config_dir, hierarchy);
    }

    void RunStatus::validate_recursive(nlohmann::json& current_node, const path& base_dir) {
        if (current_node.is_object()) {

            if (current_node.contains("validator") && current_node["validator"].is_string()) {
                const auto schema_file = current_node["validator"].get<string>();
                const path schema_path = base_dir / schema_file;

                nlohmann::json_schema::json_validator global_validator;
                const YNode node = YAML::LoadFile(schema_path.string());
                global_validator.set_root_schema(yaml_to_json(node));
                global_validator.validate(current_node);
                current_node.erase("validator");
            }

            for (auto& [key, value] : current_node.items()) {
                validate_recursive(value, base_dir);
            }
        }
        else if (current_node.is_array()) {
            for (auto& element : current_node) {
                validate_recursive(element, base_dir);
            }
        }
    }


    json RunStatus::config_validation(const string &configPath){
        try {
            YNode config_node = YAML::LoadFile(configPath);
            json config_json = yaml_to_json(config_node);

            // extends, validators
            config_json = extends_recursive(config_json, configPath);
            validate_recursive(config_json,  path(configPath).parent_path());

            //global validation
            path global_schema_path = path(PROJECT_ROOT_DIR)/"attack_config"/"validator"/"test_validator.yaml";
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
}