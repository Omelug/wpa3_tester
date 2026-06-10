#pragma once
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <string>
#include <nlohmann/json.hpp>

namespace wpa3_tester::suite::helper {

std::optional<nlohmann::json> load_result_json(const std::filesystem::path &test_folder);

// load all driver_names from config, empty map == config not found
std::map<std::string, std::string> load_test_drivers(const std::filesystem::path &test_folder);

// return driver or "?"
std::string get_driver(const std::map<std::string, std::string> &drivers, const std::string &actor);

// open report.md for write
std::ofstream open_report(const std::filesystem::path &report_path);

}