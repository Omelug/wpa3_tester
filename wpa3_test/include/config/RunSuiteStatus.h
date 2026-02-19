#pragma once
#include <string>
#include <nlohmann/json.hpp>
#include "system/ProcessManager.h"

namespace wpa3_tester{
    class RunSuiteStatus {
    public:
        static inline const std::filesystem::path BASE_FOLDER = std::filesystem::current_path() / "data" / "wpa3_suites";
        nlohmann::json config;
        std::string configPath;
        std::string run_folder;
        std::vector<std::string> test_paths;
        static void print_test_suite_list();
        static void print_tests_in_suite(const std::string &name);
        explicit RunSuiteStatus(const std::string &configPath);
        static nlohmann::json config_validation(const std::string &configPath);
        std::vector<std::pair<std::string, std::filesystem::path>> get_test_paths();
        void execute();
    private:
        static std::string findConfigByTestSuiteName(const std::string &name);
    };
}
