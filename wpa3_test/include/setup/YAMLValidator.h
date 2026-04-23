#pragma once
#include <nlohmann/json-schema.hpp>

class YAMLValidator: public nlohmann::json_schema::json_validator{
    nlohmann::json r_schema;
    json_validator validator;
    static void apply_defaults(nlohmann::json &config, const nlohmann::json &schema, const nlohmann::json &root_schema);
public:
    explicit YAMLValidator(const std::filesystem::path &schema_path);
    void validate(nlohmann::json &current_node) const;
};