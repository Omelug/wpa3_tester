#pragma once
#include <exception>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <ostream>
#include <string>
#include <vector>

namespace wpa3_tester{
std::string current_time_string();
std::string git_commit_hash();
std::string kernel_version();
std::string relative_from(const std::string &base_dir_name, const std::string &config_path);
//void print_exception_tree(const std::exception &e, std::ostream &os, int level = 0);
std::string join(const std::vector<std::string> &v, const std::string &sep);
void resolve_relative_paths(nlohmann::json &node, const std::filesystem::path &base_dir);
}
