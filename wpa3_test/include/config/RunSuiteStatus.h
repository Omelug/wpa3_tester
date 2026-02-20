#pragma once
#include <string>
#include <nlohmann/json.hpp>
#include "system/ProcessManager.h"

namespace wpa3_tester{
    class RunSuiteStatus {
    public:
        static inline const std::filesystem::path BASE_FOLDER = std::filesystem::current_path() / "data" / "wpa3_suites";
        nlohmann::json config;
        std::string config_path;
        std::string run_folder;
        std::vector<std::string> test_paths;
        static void print_test_suite_list();
        static void print_tests_in_suite(const std::string &ts_name);
        explicit RunSuiteStatus(const std::string &config_path, std::string suite_name = "");
        static nlohmann::json config_validation(const std::string &config_path);
        std::vector<std::pair<std::string, std::filesystem::path>> get_test_paths();
        void execute();
        static std::string findConfigByTestSuiteName(const std::string &name);
    };
}
