#pragma once
#include <string>
#include <nlohmann/json.hpp>
#include "system/ProcessManager.h"

namespace wpa3_tester{
    class RunSuiteStatus {
        static size_t check_vars_len_same(nlohmann::basic_json<> basic_json);

    public:
        bool only_stats = false;
        static inline const std::filesystem::path BASE_FOLDER = std::filesystem::current_path() / "data" / "wpa3_suites";
        nlohmann::json config;
        std::string config_path;
        std::string run_folder;
        std::vector<std::string> test_paths;
        static void print_test_suite_list();
        static void print_tests_in_suite(const std::string &ts_name);
        explicit RunSuiteStatus(const std::string &config_path, std::string suite_name = "");
        static nlohmann::json config_validation(const std::string &config_path);
        void defined_by_path(nlohmann::basic_json<> source_j, const std::string &source_name, std::vector<std::pair<std::string, std::filesystem
                             ::path>> &test_map) const;
        static void defined_by_generator(nlohmann::basic_json<> source_info, const std::string &source_name,
                                         const std::filesystem::path &test_config_folder,
                                         std::vector<std::pair<std::string, std::filesystem::path>> &test_map);
        std::vector<std::pair<std::string, std::filesystem::path>> get_test_paths();
        void execute();
        static std::string findConfigByTestSuiteName(const std::string &name);
    };
}
