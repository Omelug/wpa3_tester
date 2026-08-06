#pragma once
#include <nlohmann/json.hpp>
#include <yaml-cpp/yaml.h>
#include "vector"
#include <unordered_map>

namespace wpa3_tester{
nlohmann::json yaml_to_json(const YAML::Node &node);
nlohmann::json yaml_to_json_with_marks(const YAML::Node &node, const std::string &current_path,
										std::unordered_map<std::string, YAML::Mark> &line_map);
void deep_merge(nlohmann::json &base, const nlohmann::json &patch);
nlohmann::json resolve_extends(nlohmann::json current_node, const std::filesystem::path &base_dir,
								std::vector<std::string> &hierarchy
);
void save_yaml(const nlohmann::json &config, const std::filesystem::path &out_path);
}
