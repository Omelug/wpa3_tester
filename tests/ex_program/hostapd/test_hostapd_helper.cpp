#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>

#include "config/global_config.h"
#include "ex_program/hostapd/hostapd_helper.h"
#include "system/hw_capabilities.h"

using namespace std;
using namespace filesystem;
using json = nlohmann::json;
using namespace wpa3_tester;

TEST_CASE("get_hostapd - empty version returns system default") {
    string result = hostapd::get_hostapd("");
    CHECK((result == "hostapd"));
}

TEST_CASE("get_hostapd - returns existing binary if found") {
    path test_folder = temp_directory_path() / "hostapd_test_existing";
    remove_all(test_folder);
    create_directories(test_folder);

    path mock_binary = test_folder / "hostapd_2_10";
    ofstream(mock_binary) << "mock binary";

    get_global_config()["paths"]["hostapd"]["hostapd_build_folder"] = test_folder.string();
    string result = hostapd::get_hostapd("2.10");

    CHECK((result == mock_binary.string()));
    CHECK(exists(mock_binary));
    remove_all(test_folder);
}

TEST_CASE("get_hostapd - throws when binary doesn't exist and repo not available"
    * doctest::skip(true)) {
    path test_folder = temp_directory_path() / "hostapd_test_nonexistent";
    remove_all(test_folder);

    get_global_config()["paths"]["hostapd"]["hostapd_build_folder"] = test_folder.string();

    string result2_10 = hostapd::get_hostapd("2.10");
    CHECK(( (test_folder/ "hostapd_2_10").string() == result2_10));
    CHECK(exists(result2_10));

    string result2_9 = hostapd::get_hostapd("2.9");
    CHECK(((test_folder/ "hostapd_2_9").string() == result2_9));
    CHECK(exists(result2_9));

    MESSAGE(hw_capabilities::run_cmd_output({"ls", test_folder.string()}));

    remove_all(test_folder);
}

