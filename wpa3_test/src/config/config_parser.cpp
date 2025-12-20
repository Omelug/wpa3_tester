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
        YNode config_node = YAML::LoadFile(this->finalPath);
        fs::path schema_path = fs::path(PROJECT_ROOT_DIR) / "attack_config" / "validator" / "test_validator.yaml";
        YAML::Node schema_node = YAML::LoadFile(schema_path.string());

        nlohmann::json_schema::json_validator validator;
        validator.set_root_schema(yaml_to_json(schema_node));

        nlohmann::json_schema::basic_error_handler err;
        validator.validate(yaml_to_json(config_node), err);

    } catch (const domain_error &e) {
        throw config_error::format("Schema error: {}", e.what());
    } catch (const invalid_argument &e) {
        throw config_error::format( "Error in config: {}", e.what());
    } catch (const exception& e) {
        throw config_error::format("Config validation error: {}", e.what());
    }
}