#pragma once
#include <filesystem>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace wpa3_tester{
std::string current_time_string();
std::string git_commit_hash();
std::string kernel_version();
std::string relative_from(const std::string &base_dir_name, const std::filesystem::path &config_path);
//void print_exception_tree(const std::exception &e, std::ostream &os, int level = 0);
std::string join(const std::vector<std::string> &v, const std::string &sep);
void resolve_relative_paths(nlohmann::json &node, const std::filesystem::path &base_dir);

// Creates directories and sets world read+write+execute (0777) permissions
void create_public_dirs(const std::filesystem::path &p);
void create_public_dirs(const std::filesystem::path &p, std::error_code &ec);
// Sets file to 0666 (rw-rw-rw-) or directory to 0777 (rwxrwxrwx) permissions
void set_public_perms(const std::filesystem::path &p);
void copy_f(const std::filesystem::path &src, const std::filesystem::path &dst);
}
