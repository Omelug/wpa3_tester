#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <filesystem>
#include <fstream>
#include <string>
#include <doctest/doctest.h>

#include "config/RunStatus.h"
#include "logger/error_log.h"

using namespace std;
using namespace wpa3_tester;
using namespace filesystem;

TEST_CASE("RunStatus constructor - config file not found"){
    string non_existent_config = "/path/to/non/existent/config.yaml";
    CHECK_THROWS_AS(RunStatus rs(non_existent_config), wpa3_tester::config_err);
}

TEST_CASE("RunStatus constructor - missing name field"){
    path test_dir = temp_directory_path() / "attack_config" / "test_runstatus_missing_name";
    path config_file = test_dir / "test_config.yaml";
    create_directories(test_dir);

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

TEST_CASE("RunStatus constructor - with explicit test name"){
    path test_dir = temp_directory_path() / "attack_config" / "test_runstatus_explicit_name";
    path config_file = test_dir / "test_config.yaml";
    create_directories(test_dir);

    ofstream config(config_file);
    config << R"(
name: "default_name"
attacker_module: "test_module"
actors:
  test_actor:
    source: internal
)";
    config.close();

    RunStatus rs(config_file.string(), "explicit_test_name");

    CHECK_EQ(rs.config_path(), config_file.string());
    CHECK_EQ(rs.config()["attacker_module"], "test_module");

    remove_all(test_dir);
}

TEST_CASE("RunStatus constructor - config validation"){
    path test_dir = temp_directory_path() / "attack_config" / "test_runstatus_validation";
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

    CHECK(rs.config().contains("name"));
    CHECK_EQ(rs.config()["name"], "test_validation");
    CHECK(rs.config().contains("attacker_module"));
    CHECK_EQ(rs.config()["attacker_module"], "test_module");
    CHECK(rs.config().contains("actors"));

    remove_all(test_dir);
}
