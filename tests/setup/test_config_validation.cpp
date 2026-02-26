#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include "config/RunStatus.h"
#include "setup/config_parser.h"
#include <filesystem>
#include <source_location>
#include <doctest/doctest.h>
#include <yaml-cpp/node/parse.h>
#include "config/RunSuiteStatus.h"

using namespace wpa3_tester;
using namespace  std;
using namespace  filesystem;
struct ConfigTestCase {
    string description;
    string input_yaml;
    string expected_yaml;
    bool should_pass = true;
};

void test_case_loop(const path& test_base, const vector<ConfigTestCase>& tests){
    for (const auto& t : tests) {
        SUBCASE(t.description.c_str()) {
            path input_path = test_base / t.input_yaml;
            RunStatus rs;
            rs.config_path = input_path.string();

            if (t.should_pass) {
                REQUIRE_NOTHROW(rs.config = RunStatus::config_validation(rs.config_path));

                path expected_path = test_base / t.expected_yaml;
                nlohmann::json expected_json = yaml_to_json(YAML::LoadFile(expected_path.string()));

                auto diff = nlohmann::json::diff(expected_json, rs.config);
                INFO("Diff (expected vs actual): " << diff.dump(4));
                INFO("Actual JSON from RunStatus: " << rs.config.dump(4));
                CHECK((rs.config == expected_json));
            } else {
                CHECK_THROWS_AS(rs.config = RunStatus::config_validation(rs.config_path), wpa3_tester::config_error);
            }
        }
    }
}

path this_file = source_location::current().file_name();
TEST_CASE("RunStatus Config Validation - Test configuration") {
    const path test_base = this_file.parent_path() / "config_validation"/"test";

    const vector<ConfigTestCase> tests = {
        {"1. Minimal not extends", "01_test_happy_path_minimal.yaml",   "01_test_happy_path_minimal.yaml", true},
        {"2. Full not extends",    "02_test_happy_path_full.yaml",      "02_test_happy_path_full.yaml",    true},
        {"3. Extends line",        "03_test_extends_line.yaml",         "01_test_happy_path_minimal.yaml", true},
        {"4. Extends V",           "04_test_extends_V.yaml",            "01_test_happy_path_minimal.yaml", true},
        {"5. Circular extends", "05_error_circular_extends.yaml",     "", false},
        {"6. Self extends", "06_error_self_extends.yaml",     "", false},
        {"7. Normal missing error", "07_error_missing_key.yaml",     "", false},
        {"8. path to folder", "01_test_happy_path_minimal.yaml",    "01_test_happy_path_minimal.yaml", true},

        // TODO valid extends multiple folders
    };
    test_case_loop(test_base, tests);
}

TEST_CASE("RunStatus Config Validation - Validator configuration"){
    const path test_base = this_file.parent_path() / "config_validation"/"validator";
    const vector<ConfigTestCase> tests = {
        {"1. validator", "01_test_validator_minimal.yaml",    "01_result_validator_minimal.yaml", true},
        {"2. validator extends", "02_test_validator_extends.yaml",    "01_result_validator_minimal.yaml", true},
        {"3. validator extends", "03_error_validator_extends.yaml",    "", false},
    };
    test_case_loop(test_base, tests);
}

TEST_CASE("RunStatus Config Validation - Test suite configuration"){
    const path test_base = this_file.parent_path() / "config_validation"/"test_suite";
    const vector<ConfigTestCase> tests = {
        {"1. test suite minimal", "01_ts_path_minimal.yaml",    "01_result_path_minimal.yaml", true},
        //{"2. generator", "02_ts_generator_vars.yaml",    "02_result_generator_vars.yaml", true},
        //{"3. validator extends", "03_error_validator_extends.yaml",    "", false},
    };
    // TODO change to suite validation test_case_loop(test_base, tests);
}

struct ConfigSuiteCase {
    string description;
    string input_ts_yaml;
    string folder_name;
};

void check_recursive_yaml(const path& expected_dir, const path& actual_dir) {
    REQUIRE(exists(expected_dir));
    REQUIRE(exists(actual_dir));

    size_t files_checked = 0;
    for (const auto& entry : recursive_directory_iterator(expected_dir)) {
        if (entry.is_regular_file() && entry.path().extension() == ".yaml") {
            path rel = relative(entry.path(), expected_dir);
            path actual_file = actual_dir / rel;

            INFO("Comparing file: " << rel.string());
            REQUIRE(exists(actual_file));

            YAML::Node expected_node = YAML::LoadFile(entry.path().string());
            YAML::Node actual_node = YAML::LoadFile(actual_file.string());

            nlohmann::json j_exp = yaml_to_json(expected_node);
            nlohmann::json j_act = yaml_to_json(actual_node);

            auto patch = nlohmann::json::diff(j_exp, j_act);
            INFO("Differences: " << patch.dump(4));

            CHECK((j_exp == j_act));
            files_checked++;
        }
    }
    CHECK((files_checked > 0));
}

void check_dir_tree_structure(const path& expected_dir, const path& actual_dir) {
    auto get_tree_structure = [](const path& base_path) {
        set<string> structure;
        for (const auto& entry : recursive_directory_iterator(base_path)) {
            structure.insert(relative(entry.path(), base_path).string());
        }
        return structure;
    };

    set<string> expected_tree = get_tree_structure(expected_dir);
    set<string> actual_tree = get_tree_structure(actual_dir);

    if (expected_tree != actual_tree) {
        for (const auto& path : expected_tree) {
            if (!actual_tree.contains(path)) {
                INFO("Missing in actual: " << path);
            }
        }
        for (const auto& path : actual_tree) {
            if (!expected_tree.contains(path)) {
                INFO("Extra in actual: " << path);
            }
        }
    }

    CHECK((expected_tree == actual_tree));
}

TEST_CASE("RunStatus - Test suite test generation") {
    const path test_base = absolute(this_file.parent_path() / "config_validation" / "test_suite");

    const vector<ConfigSuiteCase> tests = {
        //{"1. test suite minimal", "01_ts_path_minimal.yaml", "01_min"},
        {"2. generator", "02_ts_generator_vars.yaml", "02_result_generator_vars"},
        {"3. driver permutations", "03_ts_driver_permutation.yaml", "03_result_driver_permutation"}
    };

    for (const auto& t : tests) {
        SUBCASE(t.description.c_str()) {
            path ts_config_path = test_base / t.input_ts_yaml;

            RunSuiteStatus rss(ts_config_path);
            rss.run_folder = test_base / "run_out" / t.folder_name;

            if (exists(rss.run_folder)) {remove_all(rss.run_folder);}
            create_directories(rss.run_folder);

            rss.config = RunSuiteStatus::config_validation(rss.config_path);
            auto tests_paths = rss.get_test_paths();

            auto actual_dir = path(rss.run_folder);
            path expected_dir = test_base / "expected" / t.folder_name;

            CAPTURE(actual_dir.string());
            CAPTURE(expected_dir.string());

            SUBCASE("Recursive YAML comparison") {
                check_recursive_yaml(expected_dir, actual_dir);
            }
            SUBCASE("Directory tree structure comparison") {
                check_dir_tree_structure(expected_dir, actual_dir);
            }
        }
    }
}
