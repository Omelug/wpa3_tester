#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <string>
#include <filesystem>
#include <chrono>
#include <regex>

#include "logger/error_log.h"
#include "config/RunStatus.h"

using namespace std;
using namespace wpa3_tester;
using namespace filesystem;

TEST_CASE (
"current_time_string - format validation"
)
 {
    string time_str = current_time_string();

    regex time_pattern(R"(^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$)");
    CHECK(regex_match(time_str, time_pattern));

    // Check length should be exactly 19 characters (YYYY-MM-DD HH:MM:SS)
    CHECK_EQ(time_str.length(), 19);

    // Check specific separators
    CHECK_EQ(time_str[4], '-');
    CHECK_EQ(time_str[7], '-');
    CHECK_EQ(time_str[10], ' ');
    CHECK_EQ(time_str[13], ':');
    CHECK_EQ(time_str[16], ':');
}

TEST_CASE (
"current_time_string - reasonable values"
)
 {
    string time_str = current_time_string();

    //  year, month, day, hour, minute, second
    int year = stoi(time_str.substr(0, 4));
    int month = stoi(time_str.substr(5, 2));
    int day = stoi(time_str.substr(8, 2));
    int hour = stoi(time_str.substr(11, 2));
    int minute = stoi(time_str.substr(14, 2));
    int second = stoi(time_str.substr(17, 2));
    
    CHECK((year >= 2020 && year <= 2030));
    CHECK((month >= 1 && month <= 12));
    CHECK((day >= 1 && day <= 31));
    CHECK((hour >= 0 && hour <= 23));
    CHECK((minute >= 0 && minute <= 59));
    CHECK((second >= 0 && second <= 59));
}

TEST_CASE (
"current_time_string - consistency"
)
 {
    string time1 = current_time_string();
    // small delay to ensure different timestamps
    this_thread::sleep_for(chrono::milliseconds(100));
    string time2 = current_time_string();
    CHECK_EQ(time1.length(), time2.length());

    CHECK((time2 >= time1));
}

TEST_CASE (
"relative_from - basic functionality"
)
 {
    path test_base = current_path() / "test_relative_base";
    path attack_config = test_base / "attack_config" / "subdir" / "nested" / "test_config.yaml";
    create_directories(attack_config.parent_path());
    
    string result = relative_from("attack_config", attack_config.string());
    CHECK_EQ(result, "subdir/nested");

    remove_all(test_base);
}

TEST_CASE (
"relative_from - direct child"
)
 {
    path test_base = current_path() / "test_relative_direct";
    path attack_config = test_base / "attack_config" / "direct_config.yaml";
    
    create_directories(attack_config.parent_path());
    
    string result = relative_from("attack_config", attack_config.string());
    CHECK_EQ(result, ".");
    remove_all(test_base);
}

TEST_CASE (
"relative_from - base not found"
)
 {
    path test_base = current_path() / "test_relative_notfound";
    path other_dir = test_base / "other_directory" / "config.yaml";
    
    create_directories(other_dir.parent_path());

    CHECK_THROWS_AS(relative_from("attack_config", other_dir.string()), wpa3_tester::config_err);

    remove_all(test_base);
}

TEST_CASE (
"relative_from - complex nested structure"
)
 {
    path test_base = current_path() / "test_relative_complex";
    path attack_config = test_base / "project" / "attack_config" / "Enterprise" / "reflection_attack" / "test.yaml";
    create_directories(attack_config.parent_path());
    
    string result = relative_from("attack_config", attack_config.string());

    CHECK_EQ(result, "Enterprise/reflection_attack");
    remove_all(test_base);
}

TEST_CASE (
"relative_from - absolute path handling"
)
 {
    path test_base = current_path() / "test_relative_absolute";
    path attack_config = test_base / "attack_config" / "absolute_test.yaml";
    
    create_directories(attack_config.parent_path());

    string abs_path = absolute(attack_config).string();
    string result = relative_from("attack_config", abs_path);
    
    CHECK_EQ(result, ".");
    remove_all(test_base);
}

TEST_CASE (
"relative_from - single level nesting"
)
 {
    path test_base = current_path() / "test_relative_single";
    path attack_config = test_base / "attack_config" / "single" / "config.yaml";
    create_directories(attack_config.parent_path());
    
    string result = relative_from("attack_config", attack_config.string());
    
    CHECK_EQ(result, "single");
    remove_all(test_base);
}

TEST_CASE (
"RunStatus constructor - config file not found"
)
 {
    string non_existent_config = "/path/to/non/existent/config.yaml";
    CHECK_THROWS_AS(RunStatus rs(non_existent_config), wpa3_tester::config_err);
}

TEST_CASE (
"RunStatus constructor - missing name field"
)
 {
    path test_dir = temp_directory_path() / "attack_config" / "test_runstatus_missing_name";
    path config_file = test_dir / "test_config.yaml";
    create_directories(test_dir);

    // conifig without name field
    ofstream config(config_file);
    config << R"(
attacker_module: "test_module"
actors:
  test_actor:
    source: internal
)";
    config.close();
    
    CHECK_THROWS_AS(RunStatus rs(config_file.string()), wpa3_tester::config_err);
    
    remove_all(test_dir);
}

TEST_CASE (
"RunStatus constructor - with explicit test name"
)
 {
    path test_dir = temp_directory_path() / "attack_config" / "test_runstatus_explicit_name";
    path config_file = test_dir / "test_config.yaml";
    create_directories(test_dir);

    // valid config
    ofstream config(config_file);
    config << R"(
name: "default_name"
attacker_module: "test_module"
actors:
  test_actor:
    source: internal
)";
    config.close();

    // Override with explicit test name
    RunStatus rs(config_file.string(), "explicit_test_name");

    CHECK_EQ(rs.config_path, config_file.string());
    CHECK_EQ(rs.config["attacker_module"], "test_module");
    
    remove_all(test_dir);
}

TEST_CASE (
"RunStatus constructor - config validation"
)
 {
    path test_dir = temp_directory_path() / "attack_config"/ "test_runstatus_validation";
    path config_file = test_dir / "test_config.yaml";
    create_directories(test_dir);

    ofstream config(config_file);
    config << R"(
name: "test_validation"
attacker_module: "test_module"
actors:
  test_actor:
    source: internal
    selection:
      iface: "wlan0"
)";
    config.close();

    RunStatus rs(config_file.string());

    CHECK((rs.config.contains("name")));
    CHECK_EQ(rs.config["name"], "test_validation");
    CHECK((rs.config.contains("attacker_module")));
    CHECK_EQ(rs.config["attacker_module"], "test_module");
    CHECK((rs.config.contains("actors")));
    
    remove_all(test_dir);
}