#pragma once
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "config/RunStatus.h"

namespace wpa3_tester::suite::helper {

std::optional<nlohmann::json> load_result_json(const std::filesystem::path &test_folder);

std::unique_ptr<RunStatus> load_test_rs(const std::filesystem::path &test_folder);

// open report.md for write
std::ofstream open_report(const std::filesystem::path &report_path);

// returns test subdirectories inside suite_dir
std::vector<std::filesystem::path> get_suite_test_folders(const std::filesystem::path &suite_dir);


template<typename ParseFn>
auto collect_entries_nested(const std::filesystem::path &run_dir, ParseFn parse_fn) {
    using E = decltype(parse_fn(std::declval<const std::filesystem::path &>()));
    std::vector<E> entries;
    for (const auto &src_dir : std::filesystem::directory_iterator(run_dir)) {
        if (!src_dir.is_directory()) continue;
        for (const auto &entry : std::filesystem::directory_iterator(src_dir.path())) {
            if (!entry.is_directory()) continue;
            if (!std::filesystem::exists(entry.path() / TEST_CONFIG_NAME)) continue;
            entries.push_back(parse_fn(entry.path()));
        }
    }
    return entries;
}

template<typename Entry>
std::vector<Entry> get_results_default(const std::filesystem::path &run_dir) {
    return collect_entries_nested(run_dir, Entry::parse);
}

}
