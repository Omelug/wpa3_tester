#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <chrono>
#include <fstream>
#include <filesystem>
#include <thread>
#include "config/Actor_Config/Actor_Config_sim.h"
#include "logger/devices.h"
#include "logger/error_log.h"
#include "root_dir_helper.h"
#include "system/utils.h"

using namespace std;
using namespace wpa3_tester;

namespace{

// mirrors device_path() in devices.cpp (data/devices lives next to wpa3_test/); not exposed via devices.h
// must be recomputed after root_dir() is overridden by IsolatedRootDir, not cached as a static const.
filesystem::path device_root(){ return root_dir().parent_path() / "data" / "devices"; }

ActorPtr make_actor(const string &permanent_mac, const bool ghz5 = true){
    ActorPtr actor(make_shared<Actor_Config_sim>(nlohmann::json::object()));
    actor[SK::permanent_mac] = permanent_mac;
    actor[SK::source] = "unit_test";
    actor[BK::GHz5] = ghz5;
    return actor;
}

// only regular *.json snapshot files, skips the last.json symlink
vector<filesystem::path> snapshot_files(const filesystem::path &dev_dir){
    vector<filesystem::path> out;
    for(const auto &entry: filesystem::directory_iterator(dev_dir)){
        if(entry.is_symlink()) continue;
        if(!entry.is_regular_file()) continue;
        if(entry.path().extension() != ".json") continue;
        out.push_back(entry.path());
    }
    return out;
}
}

TEST_CASE("add_device - throws without permanent_mac"){
    const ActorPtr actor(make_shared<Actor_Config_sim>(nlohmann::json::object()));
    CHECK_THROWS_AS(report::add_device(actor), config_err);
}

TEST_CASE("add_device - first call creates a new device, second identical call does not"){
    const test_helpers::IsolatedRootDir isolated("devices_test_1");
    const string mac = "aa:bb:cc:dd:ee:01";

    const auto actor = make_actor(mac);
    CHECK(report::add_device(actor));
    CHECK_FALSE(report::add_device(actor));
}

TEST_CASE("add_device - written snapshot and symlink have the expected format"){
    const test_helpers::IsolatedRootDir isolated("devices_test_2");
    const string mac = "aa:bb:cc:dd:ee:02";
    const filesystem::path dev_dir = device_root() / mac;

    const auto actor = make_actor(mac);
    REQUIRE(report::add_device(actor));

    const auto files = snapshot_files(dev_dir);
    REQUIRE_EQ(files.size(), 1);

    ifstream f(files[0]);
    const nlohmann::json record = nlohmann::json::parse(f);
    REQUIRE(record.contains("source"));
    REQUIRE(record.contains("caps"));
    CHECK_EQ(record.at("source").get<string>(), "unit_test");
    CHECK_EQ(record.at("caps"), actor->hw_info_caps_to_flat_json());

    const filesystem::path symlink_path = dev_dir / "last.json";
    REQUIRE(filesystem::is_symlink(symlink_path));
    CHECK_EQ(filesystem::read_symlink(symlink_path), files[0].filename());
}

TEST_CASE("add_device - two different records for the same device are both kept"){
    const test_helpers::IsolatedRootDir isolated("devices_test_3");
    const string mac = "aa:bb:cc:dd:ee:03";
    const filesystem::path dev_dir = device_root() / mac;

    const auto actor_a = make_actor(mac, true);
    const auto actor_b = make_actor(mac, false); // different caps -> not a duplicate

    CHECK(report::add_device(actor_a));
    this_thread::sleep_for(chrono::milliseconds(2)); // ensure distinct timestamp-based filenames
    CHECK(report::add_device(actor_b));

    const auto files = snapshot_files(dev_dir);
    CHECK_EQ(files.size(), 2);

    const filesystem::path symlink_path = dev_dir / "last.json";
    REQUIRE(filesystem::is_symlink(symlink_path));
    ifstream f(dev_dir / filesystem::read_symlink(symlink_path));
    const nlohmann::json last_record = nlohmann::json::parse(f);
    CHECK_EQ(last_record.at("caps"), actor_b->hw_info_caps_to_flat_json());
}
