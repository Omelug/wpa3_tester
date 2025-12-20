#include "../../include/config/RunStatus.h"


#include <yaml-cpp/yaml.h>                 // Pro YAML::
#include <nlohmann/json.hpp>               // Pro nlohmann::json
#include <nlohmann/json-schema.hpp>     // Pro nlohmann::json_schema

#include <iostream>
#include <fstream>
using nlohmann::json;


nlohmann::json yaml_to_json(const YAML::Node& node) {
    if (node.IsScalar()) {
        try { return node.as<bool>(); } catch (...) {}
        try { return node.as<int64_t>(); } catch (...) {}
        try { return node.as<double>(); } catch (...) {}
        return node.as<std::string>();
    }
    if (node.IsSequence()) {
        auto j = nlohmann::json::array();
        for (auto const& item : node) j.push_back(yaml_to_json(item));
        return j;
    }
    if (node.IsMap()) {
        auto j = nlohmann::json::object();
        for (auto it = node.begin(); it != node.end(); ++it) {
            j[it->first.as<std::string>()] = yaml_to_json(it->second);
        }
        return j;
    }
    return nlohmann::json();
}

void RunStatus::config_validation() {
    try {
        // Načteš YAML přes standardní yaml-cpp
        YAML::Node config_node = YAML::LoadFile(this->finalPath);
        YAML::Node schema_node = YAML::LoadFile("schema.yaml");

        // Převedeš na JSON pro validátor
        nlohmann::json data = yaml_to_json(config_node);
        nlohmann::json schema = yaml_to_json(schema_node);

        // Validuješ
        nlohmann::json_schema::json_validator validator;
        validator.set_root_schema(schema);
        validator.validate(data);

        std::cout << "✓ Validace proběhla úspěšně" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Chyba: " << e.what() << std::endl;
        exit(1);
    }
}