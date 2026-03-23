#include "setup/YAMLValidator.h"

#include <nlohmann/json-schema.hpp>
#include <nlohmann/json.hpp>
#include <nlohmann/json_fwd.hpp>

#include "setup/config_parser.h"

using namespace std;
using namespace filesystem;
using namespace nlohmann;

YAMLValidator::YAMLValidator(const path &schema_path){
    const auto schema_dir = schema_path.parent_path();
    r_schema = wpa3_tester::yaml_to_json(YAML::LoadFile(schema_path.string()));
    log(wpa3_tester::LogLevel::DEBUG, r_schema.dump(2));
    size_t depth = 0;
    constexpr size_t MAX_RECURSION_DEPTH = 20;
    const json_schema::schema_loader loader = [&depth, schema_dir](const json_uri &uri, json &schema) {
        if (++depth > MAX_RECURSION_DEPTH) {
            throw std::runtime_error("Max recursion depth reached at: " + uri.to_string());
        }
        const std::string& p = uri.path();
        path ref_path;

        const std::string clean_p = (!p.empty() && p[0] == '/') ? p.substr(1) : p;

        if (clean_p.compare(0, 2, "./") == 0 || clean_p.compare(0, 3, "../") == 0) {
            ref_path = schema_dir / clean_p;
        } else if (!p.empty() && p[0] == '/') {
            ref_path = p;
        } else {
            ref_path = schema_dir / clean_p;
        }

        ref_path = weakly_canonical(ref_path);

        if (exists(ref_path)) {
            schema = wpa3_tester::yaml_to_json(YAML::LoadFile(ref_path.string()));
        } else {
            throw std::runtime_error("Schema not found: " + ref_path.string());
        }
    };
    validator = json_validator(r_schema, loader);
    validator.set_root_schema(r_schema);
}

void YAMLValidator::validate(json& current_node) const {
    apply_defaults(current_node, r_schema, r_schema);
    validator.validate(current_node);
}

void YAMLValidator::apply_defaults(json& config, const json& schema, const json& root_schema) {
    if (!schema.is_object() || !config.is_object()) return;

    // $ref
    if (schema.contains("$ref")) {
        const string ref = schema["$ref"].get<string>();
        if (ref.starts_with("#/definitions/")) {
            const string def_name = ref.substr(14);
            if (root_schema.contains("definitions") &&
                root_schema["definitions"].contains(def_name)) {
                apply_defaults(config, root_schema["definitions"][def_name], root_schema);
                }
        }
        return;
    }

    if (schema.contains("properties")) {
        for (auto& [key, prop] : schema["properties"].items()) {
            if (prop.contains("default") && !config.contains(key)) {
                config[key] = prop["default"];
            }
            if (config.contains(key)) {
                apply_defaults(config[key], prop, root_schema);
            }
        }
    }

    if (schema.contains("additionalProperties") &&
        schema["additionalProperties"].is_object()) {
        for (auto& [key, value] : config.items()) {
            apply_defaults(value, schema["additionalProperties"], root_schema);
        }
        }

    for (const auto& keyword : {"allOf", "anyOf", "oneOf"}) {
        if (schema.contains(keyword) && schema[keyword].is_array()) {
            for (const auto& sub_schema : schema[keyword]) {
                apply_defaults(config, sub_schema, root_schema);
            }
        }
    }

    for (const auto& keyword : {"then", "else"}) {
        if (schema.contains(keyword)) {
            apply_defaults(config, schema[keyword], root_schema);
        }
    }

    if (config.is_array() && schema.contains("items")) {
        for (auto& item : config) {
            apply_defaults(item, schema["items"], root_schema);
        }
    }
}