#pragma once
#include <filesystem>
#include <nlohmann/json-schema.hpp>
#include <string>
#include <unordered_map>
#include <vector>
#include <yaml-cpp/yaml.h>

class DetailedSchemaErrorHandler : public nlohmann::json_schema::basic_error_handler {
public:
	DetailedSchemaErrorHandler(
		const nlohmann::json &root_schema,
		const std::string &filename,
		const std::unordered_map<std::string, YAML::Mark> &line_map,
		std::filesystem::path schema_dir = {})
		: root_schema_(root_schema), filename_(filename), line_map_(line_map),
		  schema_dir_(std::move(schema_dir)) {}

	void error(const nlohmann::json::json_pointer &ptr,
			   const nlohmann::json &instance,
			   const std::string &message) override;

	std::string get_summary() const {
		std::string summary;
		for (const auto &err : formatted_errors_) {
			summary += err + "\n";
		}
		return summary;
	}

private:
	const nlohmann::json &root_schema_;
	std::string filename_;
	const std::unordered_map<std::string, YAML::Mark> &line_map_;
	std::filesystem::path schema_dir_;
	std::vector<std::string> formatted_errors_;
	std::string extract_custom_error(const nlohmann::json::json_pointer &ptr) const;
	std::vector<std::string> extract_deep_errors(const nlohmann::json::json_pointer &ptr,
												  const nlohmann::json &instance,
												  const std::string &message) const;
};

class YAMLValidator: public nlohmann::json_schema::json_validator{
	nlohmann::json r_schema;
	json_validator validator;
	std::filesystem::path schema_dir_;
public:
	explicit YAMLValidator(const std::filesystem::path &schema_path);
	void validate(nlohmann::json &current_node,
				  const std::unordered_map<std::string, YAML::Mark> &line_map = {},
				  const std::string &filename = "") const;
	static nlohmann::json_schema::schema_loader make_loader(const std::filesystem::path &schema_dir);
};
