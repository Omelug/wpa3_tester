#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <filesystem>
#include <fstream>
#include <string>
#include <doctest/doctest.h>

#include "default.h"
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
    path config_file = test_dir / TEST_CONFIG_NAME;
    create_directories(test_dir);

    ofstream config(config_file);
    config << R"(
attacker_module: "test_module"
actors:
  test_actor:
    source: internal
)";
    config.close();

    CHECK_THROWS_AS(RunStatus rs(config_file), wpa3_tester::config_err);

    remove_all(test_dir);
}

TEST_CASE("RunStatus constructor - with explicit test name"){
    path test_dir = temp_directory_path() / "attack_config" / "test_runstatus_explicit_name";
    path config_file = test_dir / TEST_CONFIG_NAME;
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

    RunStatus rs(config_file, "explicit_test_name");

    CHECK_EQ(rs.config_path(), config_file);
    CHECK_EQ(rs.config()["attacker_module"], "test_module");

    remove_all(test_dir);
}

TEST_CASE("RunStatus constructor - config validation"){
    path test_dir = temp_directory_path() / "attack_config" / "test_runstatus_validation";
    path config_file = test_dir / TEST_CONFIG_NAME;
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

    RunStatus rs(config_file);

    CHECK(rs.config().contains("name"));
    CHECK_EQ(rs.config()["name"], "test_validation");
    CHECK(rs.config().contains("attacker_module"));
    CHECK_EQ(rs.config()["attacker_module"], "test_module");
    CHECK(rs.config().contains("actors"));

    remove_all(test_dir);
}

// -----------------
// RunStatus::should_skip

TEST_CASE("should_skip - schema and component files are skipped regardless of location"){
    CHECK(RunStatus::should_skip(ATTACK_CONFIG / "foo" / "bar.schema.yaml"));
    CHECK(RunStatus::should_skip(ATTACK_CONFIG / "foo" / "bar.comp.yaml"));
}

TEST_CASE("should_skip - non-yaml files are skipped"){
    CHECK(RunStatus::should_skip(ATTACK_CONFIG / "foo" / "bar.txt"));
    CHECK(RunStatus::should_skip(ATTACK_CONFIG / "foo" / "bar"));
}

TEST_CASE("should_skip - anything under a top-level validator/ directory is skipped"){
    CHECK(RunStatus::should_skip(ATTACK_CONFIG / "validator" / "run_config.schema.yaml"));
    CHECK(RunStatus::should_skip(ATTACK_CONFIG / "validator" / "notes.yaml"));
}

TEST_CASE("should_skip - nested validator/ or target/ directories are skipped"){
    CHECK(RunStatus::should_skip(ATTACK_CONFIG / "mc_mitm" / "validator" / "extra.yaml"));
    CHECK(RunStatus::should_skip(ATTACK_CONFIG / "mc_mitm" / "target" / "extra.yaml"));
}

TEST_CASE("should_skip - top-level global_config.yaml is skipped"){
    CHECK(RunStatus::should_skip(ATTACK_CONFIG / "global_config.yaml"));
}

TEST_CASE("should_skip - ordinary attack config yaml is not skipped"){
    CHECK_FALSE(RunStatus::should_skip(ATTACK_CONFIG / "mc_mitm" / "mc_mitm_sim.yaml"));
}
