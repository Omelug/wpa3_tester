#pragma once
#include "config/RunStatus.h"
#include "logger/error_log.h"
#include <yaml-cpp/yaml.h>
#include <nlohmann/json.hpp>
#include "vector"

namespace wpa3_tester{
    nlohmann::json yaml_to_json(const YAML::Node& node);
    void deep_merge(nlohmann::json& base, const nlohmann::json& patch);
    nlohmann::json resolve_extends(nlohmann::json current_node, const std::filesystem::path& base_dir, std::vector<std::string>& hierarchy);
}