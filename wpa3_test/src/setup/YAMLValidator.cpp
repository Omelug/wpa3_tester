#include "setup/YAMLValidator.h"
#include <nlohmann/json-schema.hpp>

#include "logger/error_log.h"
#include "setup/config_parser.h"

using namespace std;
using namespace filesystem;
using namespace nlohmann;

YAMLValidator::YAMLValidator(const path &schema_path) {
	const auto schema_dir = schema_path.parent_path();
	r_schema = wpa3_tester::yaml_to_json(YAML::LoadFile(schema_path.string()));

	const json_schema::schema_loader loader = [&schema_dir](const json_uri &uri, json &schema) {
		const string &p = uri.path();
		const string clean_p = !p.empty() && p[0] == '/' ? p.substr(1) : p;
		const path ref_path = weakly_canonical(schema_dir / clean_p);

		if (!exists(ref_path))
			throw wpa3_tester::run_err("Schema not found: " + ref_path.string());

		schema = wpa3_tester::yaml_to_json(YAML::LoadFile(ref_path.string()));
	};

	validator = json_validator(r_schema, loader);
}

void YAMLValidator::validate(json &current_node) const {
	auto patch = validator.validate(current_node);
	current_node = current_node.patch(patch);
}