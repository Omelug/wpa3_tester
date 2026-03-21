#include <doctest.h>
#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>
#include "config/global_config.h"
#include "logger/error_log.h"

using namespace std;
using namespace wpa3_tester;
using namespace filesystem;

struct ConfigFixture {
    path dir;

    explicit ConfigFixture(const string& name) : dir(current_path() / name) {
        create_directories(dir / "attack_config");
    }

    void write(const string& content) const {
        ofstream f(dir / "attack_config" / "global_config.yaml");
        f << content;
    }

    ~ConfigFixture() { remove_all(dir); }
};


TEST_CASE("get_global_config - normal loading") {
    ConfigFixture f("test_config");
    f.write(R"(
paths:
  hostapd:
    hostapd_build_folder: "/test/hostapd"
actors:
  conn_table: "./test_table.csv"
  ignore_interfaces: [wlan0, wlan1]
)");
    nlohmann::json& config = get_global_config(f.dir, true);
    REQUIRE(config.contains("paths"));
    REQUIRE(config.contains("actors"));
    INFO(config["paths"]["hostapd"].dump());
    CHECK((config["paths"]["hostapd"].at("hostapd_build_folder").get<string>() == "/test/hostapd"));
    CHECK((config["actors"]["conn_table"] == "./test_table.csv"));
    CHECK((config["actors"]["ignore_interfaces"].size() == 2));
}

TEST_CASE("get_global_config - file not found") {
    ConfigFixture f("non_existent_config");
    remove_all(f.dir);
    CHECK_THROWS_AS(get_global_config(f.dir, true), config_err);
}

TEST_CASE("get_global_config - invalid YAML") {
    ConfigFixture f("invalid_yaml_config");
    f.write(R"(
paths:
  invalid_yaml: [unclosed array
)");
    CHECK_THROWS_AS(get_global_config(f.dir, true), config_err);
}

TEST_CASE("get_global_config - static cache") {
    ConfigFixture f("cache_test_config");
    f.write(R"(test_value: "original")");

    nlohmann::json& config1 = get_global_config(f.dir, true);
    CHECK((config1["test_value"] == "original"));

    f.write(R"(test_value: "modified")");

    nlohmann::json& config2 = get_global_config(f.dir, false);
    CHECK((config2["test_value"] == "original"));
    CHECK((&config1 == &config2));
}

TEST_CASE("get_global_config - empty file") {
    ConfigFixture f("empty_config");
    f.write("");
    nlohmann::json& config = get_global_config(f.dir, true);
    CHECK(config.empty());
}