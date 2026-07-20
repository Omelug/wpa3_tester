#include "setup/YAMLValidator.h"
#include <nlohmann/json-schema.hpp>
#include <sstream>
#include "logger/error_log.h"
#include "setup/config_parser.h"

using namespace std;
using namespace filesystem;
using namespace nlohmann;

void DetailedSchemaErrorHandler::error(const nlohmann::json::json_pointer &ptr,
               const nlohmann::json &instance,
               const std::string &message){
    nlohmann::json_schema::basic_error_handler::error(ptr, instance, message);

    std::ostringstream ss;
    std::string path_str = ptr.empty() ? "/" : ptr.to_string();

    ss << "\n[Validation Error]";

    auto it = line_map_.find(path_str);
    if(it != line_map_.end() && it->second.line >= 0){
        ss << "\n  File Location: " << filename_ << ":" << (it->second.line + 1) << ":" << (it->second.column + 1);
    }

    ss << "\n  Path: " << path_str;
    ss << "\n  Details: " << message;

    if(!instance.is_null() && !instance.is_object() && !instance.is_array()){
        ss << "\n  Provided Value: " << instance.dump();
    }

    auto deep = extract_deep_errors(ptr, instance, message);
    if(!deep.empty()){
        for(const auto &d : deep) ss << "\n  " << d;
    } else {
        std::string custom_err = extract_custom_error(ptr);
        if(!custom_err.empty()) ss << "\n  " << custom_err;
    }

    formatted_errors_.push_back(ss.str());
}

std::string DetailedSchemaErrorHandler::extract_custom_error(
    const nlohmann::json::json_pointer &ptr) const {
    try {
        std::string ptr_str = ptr.to_string();
        if(ptr_str.empty() || ptr_str == "/") return "";

        std::stringstream ss(ptr_str);
        std::string token;
        std::string schema_path;

        while(std::getline(ss, token, '/')){
            if(token.empty()) continue;
            size_t pos = 0;
            while((pos = token.find("~1", pos)) != std::string::npos){ token.replace(pos, 2, "/"); pos++; }
            pos = 0;
            while((pos = token.find("~0", pos)) != std::string::npos){ token.replace(pos, 2, "~"); pos++; }
            schema_path += "/properties/" + token;
        }

        nlohmann::json::json_pointer schema_ptr(schema_path);
        if(root_schema_.contains(schema_ptr)){
            const auto &target_node = root_schema_[schema_ptr];
            if(target_node.contains("errorMessage"))
                return "Rule Violation: " + target_node["errorMessage"].get<std::string>();
            if(target_node.contains("description"))
                return "Description: " + target_node["description"].get<std::string>();
        }
    } catch(...) {}
    return "";
}

std::vector<std::string> DetailedSchemaErrorHandler::extract_deep_errors(
    const nlohmann::json::json_pointer &ptr,
    const nlohmann::json &instance,
    const std::string &message) const {

    std::vector<std::string> results;

    // Parse actor name from "validation failed for additional property 'X'"
    const std::string needle = "validation failed for additional property '";
    size_t pos = message.find(needle);
    if(pos == std::string::npos) return results;
    size_t name_start = pos + needle.size();
    size_t name_end = message.find('\'', name_start);
    if(name_end == std::string::npos) return results;
    std::string prop_name = message.substr(name_start, name_end - name_start);

    if(!instance.is_object() || !instance.contains(prop_name)) return results;
    const nlohmann::json &prop_value = instance[prop_name];

    // Build schema path: /actors → /properties/actors/additionalProperties
    std::string schema_path;
    {
        std::string ptr_str = ptr.to_string();
        std::stringstream ss(ptr_str);
        std::string token;
        while(std::getline(ss, token, '/')){
            if(token.empty()) continue;
            size_t p = 0;
            while((p = token.find("~1", p)) != std::string::npos){ token.replace(p, 2, "/"); p++; }
            p = 0;
            while((p = token.find("~0", p)) != std::string::npos){ token.replace(p, 2, "~"); p++; }
            schema_path += "/properties/" + token;
        }
    }
    schema_path += "/additionalProperties";

    nlohmann::json::json_pointer ap_ptr(schema_path);
    if(!root_schema_.contains(ap_ptr)) return results;

    // Resolve local $ref (e.g. '#/$defs/Actor')
    const nlohmann::json *resolved = &root_schema_[ap_ptr];
    if(resolved->contains("$ref")){
        const std::string &ref = (*resolved)["$ref"].get<std::string>();
        if(!ref.empty() && ref[0] == '#'){
            nlohmann::json::json_pointer ref_ptr(ref.substr(1));
            if(root_schema_.contains(ref_ptr))
                resolved = &root_schema_[ref_ptr];
        }
    }

    if(!resolved->contains("allOf")) return results;

    for(const auto &item : (*resolved)["allOf"]){
        try{
            nlohmann::json_schema::json_validator temp_v(item);
            nlohmann::json copy = prop_value;
            nlohmann::json_schema::basic_error_handler eh;
            temp_v.validate(copy, eh);
            if(!eh) continue;

            std::string err_msg;
            if(item.contains("errorMessage") && item["errorMessage"].is_string())
                err_msg = item["errorMessage"].get<std::string>();
            else if(item.contains("then") && item["then"].contains("errorMessage")
                    && item["then"]["errorMessage"].is_string())
                err_msg = item["then"]["errorMessage"].get<std::string>();

            if(!err_msg.empty())
                results.push_back("Rule Violation: " + err_msg);
        } catch(...) {}
    }

    return results;
}

YAMLValidator::YAMLValidator(const path &schema_path){
	const auto schema_dir = schema_path.parent_path();
	r_schema = wpa3_tester::yaml_to_json(YAML::LoadFile(schema_path.string()));

	const json_schema::schema_loader loader = [&schema_dir](const json_uri &uri, json &schema){
		const string &p = uri.path();
		const string clean_p = !p.empty() && p[0] == '/' ? p.substr(1) : p;
		const path ref_path = weakly_canonical(schema_dir / clean_p);

		if(!exists(ref_path)) throw wpa3_tester::run_err("Schema not found: " + ref_path.string());

		schema = wpa3_tester::yaml_to_json(YAML::LoadFile(ref_path.string()));
	};

	validator = json_validator(r_schema, loader);
}

void YAMLValidator::validate(json &current_node,
                              const std::unordered_map<std::string, YAML::Mark> &line_map,
                              const std::string &filename) const {
    DetailedSchemaErrorHandler err_handler(r_schema, filename, line_map);
	const auto patch = validator.validate(current_node, err_handler);
    if(err_handler){
        throw wpa3_tester::setup_err("Config error: {} \n", err_handler.get_summary());
    }
	current_node = current_node.patch(patch);
}
