#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include "config/RunStatus.h"
#include "setup/config_parser.h"
#include <fstream>
#include <filesystem>
#include <source_location>
#include <yaml-cpp/node/parse.h>

namespace fs = std::filesystem;

struct ConfigTestCase {
    std::string description;
    std::string input_yaml;
    std::string expected_yaml;
    bool should_pass = true;
};

void test_case_loop(const fs::path& test_base, const std::vector<ConfigTestCase>& tests){
    for (const auto& t : tests) {
        SUBCASE(t.description.c_str()) {
            fs::path input_path = test_base / t.input_yaml;
            wpa3_tester::RunStatus rs;
            rs.configPath = input_path.string();

            if (t.should_pass) {
                REQUIRE_NOTHROW(rs.config_validation());

                fs::path expected_path = test_base / t.expected_yaml;
                nlohmann::json expected_json = wpa3_tester::yaml_to_json(YAML::LoadFile(expected_path.string()));

                auto diff = nlohmann::json::diff(expected_json, rs.config);
                INFO("Diff (expected vs actual): " << diff.dump(4));
                INFO("Actual JSON from RunStatus: " << rs.config.dump(4));
                CHECK((rs.config == expected_json));
            } else {
                CHECK_THROWS_AS(rs.config_validation(), wpa3_tester::config_error);
            }
        }
    }
}

fs::path this_file = std::source_location::current().file_name();
TEST_CASE("RunStatus Config Validation - Test configuration") {
    const fs::path test_base = this_file.parent_path() / "config_validation"/"test";

    std::vector<ConfigTestCase> tests = {
        {"1. Minimal not extends", "01_test_happy_path_minimal.yaml",   "01_test_happy_path_minimal.yaml", true},
        {"2. Full not extends",    "02_test_happy_path_full.yaml",      "02_test_happy_path_full.yaml",    true},
        {"3. Extends line",        "03_test_extends_line.yaml",         "01_test_happy_path_minimal.yaml", true},
        {"4. Extends V",           "04_test_extends_V.yaml",            "01_test_happy_path_minimal.yaml", true},
        {"5. Circular extends", "05_error_circular_extends.yaml",     "", false},
        {"6. Self extends", "06_error_self_extends.yaml",     "", false},
        {"7. Normal missing error", "07_error_missing_key.yaml",     "", false},
        {"8. path to folder", "01_test_happy_path_minimal.yaml",    "01_test_happy_path_minimal.yaml", true},

        // TODO valids extends multiple folders
    };
    test_case_loop(test_base, tests);
}

TEST_CASE("RunStatus Config Validation - Validator configuration"){
    const fs::path test_base = this_file.parent_path() / "config_validation"/"validator";
    std::vector<ConfigTestCase> tests = {
        {"1. validator", "01_test_validator_minimal.yaml",    "01_result_validator_minimal.yaml", true},
        {"2. validator extends", "02_test_validator_extends.yaml",    "01_result_validator_minimal.yaml", true},
        {"3. validator extends", "03_error_validator_extends.yaml",    "", false},
    };
    test_case_loop(test_base, tests);
}

TEST_CASE("RunStatus Config Validation - Test suite configuration"){
    const fs::path test_base = this_file.parent_path() / "config_validation"/"test_suite";
    const std::vector<ConfigTestCase> tests = {
        {"1. test suite minimal", "01_ts_path_minimal.yaml",    "01_result_path_minimal.yaml", true},
        {"2. generator", "02_ts_generator_vars.yaml",    "02_result_generator_vars.yaml", true},
        //{"3. validator extends", "03_error_validator_extends.yaml",    "", false},
    };
    //TODO test suite testing
}

