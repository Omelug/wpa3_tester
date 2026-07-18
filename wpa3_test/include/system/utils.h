#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace wpa3_tester{
// Returns PROJECT_ROOT_DIR by default; pass a value to override it (tests use this to
// point at a temp fixture dir instead of the real wpa3_test/ source tree).
const std::filesystem::path &root_dir(const std::optional<std::filesystem::path> &set_to = std::nullopt);

std::string current_time_string();
std::string git_commit_hash();
std::string kernel_version();
std::string relative_from(const std::string &base_dir_name, const std::filesystem::path &config_path);
//void print_exception_tree(const std::exception &e, std::ostream &os, int level = 0);
std::string trim(std::string s);
std::string join(const std::vector<std::string> &v, const std::string &sep);
void resolve_relative_paths(nlohmann::json &node, const std::filesystem::path &base_dir);

// Creates directories and sets world read+write+execute (0777) permissions
void create_public_dirs(const std::filesystem::path &p);
void create_public_dirs(const std::filesystem::path &p, std::error_code &ec);
// Sets file to 0666 (rw-rw-rw-) or directory to 0777 (rwxrwxrwx) permissions
void set_public_perms(const std::filesystem::path &p);
void copy_f(const std::filesystem::path &src, const std::filesystem::path &dst);
}
