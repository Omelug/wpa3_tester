#include "../../include/config/RunStatus.h"
#include "../../include/logger/error_log.h"

#include <yaml-cpp/yaml.h>
#include <nlohmann/json.hpp>
#include <nlohmann/json-schema.hpp>

#include <iostream>
#include <fstream>

using namespace std;
using json = nlohmann::json;
using YNode = YAML::Node;
namespace fs = std::filesystem;

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
    return json();
}

void RunStatus::config_validation() {
    try {
        //TODO add posibility use templeate
        YNode config_node = YAML::LoadFile(this->finalPath);
        json config_json = yaml_to_json(config_node);

        fs::path global_schema_path = fs::path(PROJECT_ROOT_DIR) \
            / "attack_config" / "validator" / "test_validator.yaml";
        YNode global_schema_node = YAML::LoadFile(global_schema_path.string());

        nlohmann::json_schema::json_validator global_validator;
        global_validator.set_root_schema(yaml_to_json(global_schema_node));
        global_validator.validate(config_json);

        if (!config_json.contains("attack_config") || !config_json["attack_config"].is_object()) {
            throw config_error("Missing or invalid 'attack_config' section in config");
        }

        json attack_cfg = config_json["attack_config"];
        if (!attack_cfg.contains("validator") || !attack_cfg["validator"].is_string()) {
            throw config_error("'attack_config.validator' must be a string path to YAML schema");
        }

        fs::path config_path(this->finalPath);
        fs::path config_dir = config_path.parent_path();
        fs::path attack_schema_path = config_dir \
            / attack_cfg["validator"].get<string>();

        YNode attack_schema_node = YAML::LoadFile(attack_schema_path.string());
        json attack_schema_json = yaml_to_json(attack_schema_node);

        nlohmann::json_schema::json_validator attack_validator;
        attack_validator.set_root_schema(attack_schema_json);
        attack_validator.validate(attack_cfg);

    } catch (const domain_error &e) {
        throw config_error::format("Schema error: {}", e.what());
    } catch (const invalid_argument &e) {
        throw config_error::format( "Error in config: {}", e.what());
    } catch (const exception& e) {
        throw config_error::format("Config validation error: {}", e.what());
    }
}