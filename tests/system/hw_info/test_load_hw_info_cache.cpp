#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include "config/Actor_config.h"
#include "system/hw_info.h"

using namespace std;
using namespace filesystem;
using namespace wpa3_tester;
using json = nlohmann::json;

// 'lo' always present; `ip -j link show lo` reports address = 00:00:00:00:00:00
static constexpr string_view LO_MAC = "00:00:00:00:00:00";

static path write_cache(const path &dir, const string &mac, const json &entry){
    create_directories(dir);
    const path p = dir / "hw_info_cache.json";
    json obj     = json::object();
    obj[mac]     = entry;
    ofstream f(p);
    f << obj.dump(2) << '\n';
    return p;
}

// -----------------
struct Fixture {
    path tmp = temp_directory_path() / "test_hw_info_cache";
    Fixture()  { remove_all(tmp); }
    ~Fixture() { remove_all(tmp); }
};

// -----------------
TEST_CASE_FIXTURE(Fixture, "load_hw_info - cache hit restores driver_name and permanent_mac") {
    const path cache_file = write_cache(tmp, string(LO_MAC), {
        {"driver",   "stub_driver"},
        {"permanent_mac", string(LO_MAC)},
    });

    const auto actor = make_shared<Actor_config>();
    actor->set(SK::iface, "lo");
    actor->load_hw_info(cache_file);

    CHECK_EQ(actor->get(SK::driver_name),   "stub_driver");
    CHECK_EQ(actor->get(SK::permanent_mac), string(LO_MAC));
}

TEST_CASE_FIXTURE(Fixture, "load_hw_info - cache hit restores driver_hash when present") {
    const path cache_file = write_cache(tmp, string(LO_MAC), {
        {"driver",   "stub_driver"},
        {"driver_hash",   "deadbeef"},
        {"permanent_mac", string(LO_MAC)},
    });

    const auto actor = make_shared<Actor_config>();
    actor->set(SK::iface, "lo");
    actor->load_hw_info(cache_file);

    CHECK_EQ(actor->get(SK::driver_hash), "deadbeef");
}

TEST_CASE_FIXTURE(Fixture, "load_hw_info - empty driver_hash in cache is not set") {
    const path cache_file = write_cache(tmp, string(LO_MAC), {
        {"driver",   "stub_driver"},
        {"driver_hash",   ""},
        {"permanent_mac", string(LO_MAC)},
    });

    const auto actor = make_shared<Actor_config>();
    actor->set(SK::iface, "lo");
    actor->load_hw_info(cache_file);

    // from_json skips empty driver_hash
    CHECK_FALSE((*actor)[SK::driver_hash].has_value());
}

TEST_CASE_FIXTURE(Fixture, "load_hw_info - cache hit restores module_hash when present") {
    const path cache_file = write_cache(tmp, string(LO_MAC), {
        {"driver",   "stub_driver"},
        {"module_hash",   "cafebabe12345678"},
        {"permanent_mac", string(LO_MAC)},
    });

    const auto actor = make_shared<Actor_config>();
    actor->set(SK::iface, "lo");
    actor->load_hw_info(cache_file);

    CHECK_EQ(actor->get(SK::module_hash), "cafebabe12345678");
}

TEST_CASE_FIXTURE(Fixture, "load_hw_info - empty module_hash in cache is not set") {
    const path cache_file = write_cache(tmp, string(LO_MAC), {
        {"driver",   "stub_driver"},
        {"module_hash",   ""},
        {"permanent_mac", string(LO_MAC)},
    });

    const auto actor = make_shared<Actor_config>();
    actor->set(SK::iface, "lo");
    actor->load_hw_info(cache_file);

    CHECK_FALSE((*actor)[SK::module_hash].has_value());
}

// -----------------
TEST_CASE_FIXTURE(Fixture, "load_hw_info - wrong perm_mac in cache does not pollute actor") {
    // Cache contains an unrelated MAC; lo's 00:00:00:00:00:00 won't match → cache miss
    const path cache_file = write_cache(tmp, "ff:ff:ff:ff:ff:ff", {
        {"driver",   "should_not_load"},
        {"permanent_mac", "ff:ff:ff:ff:ff:ff"},
    });

    const auto actor = make_shared<Actor_config>();
    actor->set(SK::iface, "lo");
    // Cache miss → falls through to hw detection; loopback may throw — that's OK
    try { actor->load_hw_info(cache_file); } catch(...) {}

    CHECK_NE((*actor)[SK::driver_name].value_or(""), "should_not_load");
}
