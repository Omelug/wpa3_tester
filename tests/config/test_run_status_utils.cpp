#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <filesystem>
#include <fstream>
#include <string>
#include <doctest/doctest.h>

#include "default.h"
#include "config/RunStatus.h"
#include "config/Actor_Config/Actor_Config_sim.h"
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

// -----------------
// RunStatus::load_actor_interface_mapping

TEST_CASE("load_actor_interface_mapping - round-trips actors written by save_actor_interface_mapping"){
    const path test_dir = temp_directory_path() / "test_load_actor_interface_mapping";
    create_directories(test_dir);

    RunStatus rs;
    rs.run_folder(test_dir);

    const auto make = [](const string &name, const string &iface, const string &mac, const string &driver,
                        const string &channel
    ){
        const auto a = make_shared<Actor_Config_sim>();
        a->set(SK::source, "simulation");
        a->set(SK::actor_name, name);
        a->set(SK::iface, iface);
        a->set(SK::mac, mac);
        a->set(SK::driver_name, driver);
        a->set(SK::channel, channel);
        return ActorPtr(a);
    };
    rs.actors.emplace("sta", make("sta", "wlan0", "02:00:00:00:00:01", "ath9k", "6"));
    rs.actors.emplace("ap", make("ap", "wlan1", "02:00:00:00:00:02", "mac80211_hwsim", "1"));

    rs.save_actor_interface_mapping();
    REQUIRE(exists(test_dir / "mapping.csv"));

    rs.actors.clear();
    rs.load_actor_interface_mapping();

    REQUIRE_EQ(rs.actors.size(), 2);
    REQUIRE(rs.actors.contains("sta"));
    REQUIRE(rs.actors.contains("ap"));

    const auto &sta = rs.actors.at("sta");
    CHECK_EQ(sta.get(SK::iface), "wlan0");
    CHECK_EQ(sta.get(SK::mac), "02:00:00:00:00:01");
    CHECK_EQ(sta.get(SK::driver_name), "ath9k");
    CHECK_EQ(sta.get(SK::channel), "6");

    const auto &ap = rs.actors.at("ap");
    CHECK_EQ(ap.get(SK::iface), "wlan1");
    CHECK_EQ(ap.get(SK::channel), "1");

    remove_all(test_dir);
}

TEST_CASE("load_actor_interface_mapping - missing mapping.csv leaves actors untouched"){
    const path test_dir = temp_directory_path() / "test_load_actor_interface_mapping_missing";
    remove_all(test_dir);
    create_directories(test_dir);

    RunStatus rs;
    rs.run_folder(test_dir);

    CHECK_NOTHROW(rs.load_actor_interface_mapping());
    CHECK(rs.actors.empty());

    remove_all(test_dir);
}

// -----------------
// RunStatus::save_result / load_result

TEST_CASE("save_result - load_result round-trips a json object"){
    const path test_dir = temp_directory_path() / "test_save_load_result";
    create_directories(test_dir);

    RunStatus rs;
    rs.run_folder(test_dir);

    const nlohmann::json original = {{"passed", true}, {"count", 3}};
    rs.save_result(original);

    REQUIRE(exists(test_dir / RESULT_NAME));
    CHECK_EQ(rs.load_result(), original);

    remove_all(test_dir);
}

TEST_CASE("load_result - throws stats_err when result.json is missing"){
    const path test_dir = temp_directory_path() / "test_load_result_missing";
    remove_all(test_dir);
    create_directories(test_dir);

    RunStatus rs;
    rs.run_folder(test_dir);

    CHECK_THROWS_AS(rs.load_result(), stats_err);

    remove_all(test_dir);
}

TEST_CASE("load_actor_interface_mapping - malformed rows are skipped, not thrown"){
    const path test_dir = temp_directory_path() / "test_load_actor_interface_mapping_malformed";
    create_directories(test_dir);

    ofstream ofs(test_dir / "mapping.csv");
    ofs << "Type,ActorName,Interface,MAC,Driver,channel,json_obj\n";
    ofs << "simulation,broken_row\n"; // too few columns
    ofs.close();

    RunStatus rs;
    rs.run_folder(test_dir);

    CHECK_NOTHROW(rs.load_actor_interface_mapping());
    CHECK(rs.actors.empty());

    remove_all(test_dir);
}
