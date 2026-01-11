#include "config/RunStatus.h"
#include "logger/error_log.h"
#include <yaml-cpp/yaml.h>
#include <nlohmann/json.hpp>
#include <nlohmann/json-schema.hpp>
namespace wpa3_tester{
    using namespace std;
    using json = nlohmann::json;
    using YNode = YAML::Node;
    using  namespace filesystem;

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
        if (current_node.is_object() && current_node.contains("extends")) {
            path parent_path = absolute(base_dir / current_node["extends"].get<string>());

            string parent_path_str = parent_path.string();
            if (std::find(hierarchy.begin(), hierarchy.end(), parent_path_str) != hierarchy.end()) {
                throw config_error("Circular inheritance detected! File already in hierarchy: " + parent_path_str);
            }

            hierarchy.push_back(parent_path_str);

            const YNode parent_yaml = YAML::LoadFile(parent_path.string());
            json parent_json = yaml_to_json(parent_yaml);

            parent_json = resolve_extends(parent_json, parent_path.parent_path(), hierarchy);

            current_node.erase("extends");
            deep_merge(parent_json, current_node);
            return parent_json;
        }
        return current_node;
    }

    void RunStatus::config_validation() {
        try {
            YNode config_node = YAML::LoadFile(this->configPath);
            json config_json = yaml_to_json(config_node);

            path global_schema_path = path(PROJECT_ROOT_DIR)/"attack_config"/"validator"/"test_validator.yaml";
            YNode global_schema_node = YAML::LoadFile(global_schema_path.string());

            nlohmann::json_schema::json_validator global_validator;
            global_validator.set_root_schema(yaml_to_json(global_schema_node));
            global_validator.validate(config_json);

            path config_path(this->configPath);
            path config_dir = config_path.parent_path();
            vector<string> hierarchy;
            config_json = resolve_extends(config_json, config_dir, hierarchy);
            this->template_hierarchy = hierarchy;

            // -------- attack config validation --------------
            json attack_cfg = config_json["attack_config"];
            path attack_schema_path = config_dir / attack_cfg["validator"].get<string>();

            YNode attack_schema_node = YAML::LoadFile(attack_schema_path.string());
            json attack_schema_json = yaml_to_json(attack_schema_node);

            nlohmann::json_schema::json_validator attack_validator;
            attack_validator.set_root_schema(attack_schema_json);
            attack_validator.validate(attack_cfg);

            this->config = config_json;

        } catch (const domain_error &e) {
            throw config_error(string("Schema error: ") + e.what());
        } catch (const invalid_argument &e) {
            throw config_error(string("Error in config: ") + e.what());
        } catch (const exception& e) {
            throw config_error(string("Config validation error: ") + e.what());
        }
    }
}