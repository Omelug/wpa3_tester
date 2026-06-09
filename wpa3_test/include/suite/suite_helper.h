#pragma once
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <string>
#include <nlohmann/json.hpp>

namespace wpa3_tester::suite::helper {

// Načte result.json z test_folder, pokud existuje
std::optional<nlohmann::json> load_result_json(const std::filesystem::path &test_folder);

// Načte driver_name pro každého aktéra z test_config.yaml; prázdná mapa = config nenalezen
std::map<std::string, std::string> load_test_drivers(const std::filesystem::path &test_folder);

// Vrátí driver pro daného aktéra z načtené mapy, nebo "?" pokud není
std::string get_driver(const std::map<std::string, std::string> &drivers, const std::string &actor);

// Otevře report.md pro zápis; loguje chybu, pokud se nepodaří
std::ofstream open_report(const std::filesystem::path &report_path);

}