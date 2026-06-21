#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <nlohmann/json.hpp>

#include "default.h"
#include "suite/result_helper.h"

using namespace std;
using namespace filesystem;
using namespace wpa3_tester::suite::helper;
using json = nlohmann::json;

// minimal aggregate struct
struct TestEntry {
    string name{};
	[[maybe_unused]] int count{};
	[[maybe_unused]] bool flag{};
    optional<bool> opt_flag{};
    optional<string> opt_name{};
};

// writes result.json into a temp dir, returns the dir path
static path make_result_dir(const json &j) {
    const path dir = temp_directory_path() / "wpa3_result_helper_test";
    create_directories(dir);
    ofstream(dir / RESULT_NAME) << j.dump();
    return dir;
}

// -----------------
TEST_CASE("load_result_default - all fields present") {
    const auto dir = make_result_dir({
        {"name",     "foo"},
        {"count",    42},
        {"flag",     true},
        {"opt_flag", false},
        {"opt_name", "bar"},
    });

    const auto [name, count, flag, opt_flag, opt_name] = load_result_default<TestEntry>(dir);
    CHECK_EQ(name,  "foo");
    CHECK_EQ(count, 42);
    CHECK_EQ(flag,  true);
    REQUIRE(opt_flag.has_value());
    CHECK_EQ(opt_flag.value(), false);
    REQUIRE(opt_name.has_value());
    CHECK_EQ(opt_name.value(), "bar");
}

TEST_CASE("load_result_default - string default is '-'") {
    const auto dir = make_result_dir({{"count", 1}});

    const auto e = load_result_default<TestEntry>(dir);
    CHECK_EQ(e.name, "-");
}

TEST_CASE("load_result_default - optional<string> default is 'N/A'") {
    const auto dir = make_result_dir({{"count", 1}});

    const auto e = load_result_default<TestEntry>(dir);
    REQUIRE(e.opt_name.has_value());
    CHECK_EQ(e.opt_name.value(), "N/A");
}

TEST_CASE("load_result_default - optional<bool> default is nullopt") {
    const auto dir = make_result_dir({{"flag", true}});

    const auto e = load_result_default<TestEntry>(dir);
    CHECK_FALSE(e.opt_flag.has_value());
}

TEST_CASE("load_result_default - no result.json returns entry_defaults") {
    const path dir = temp_directory_path() / "wpa3_no_result";
    create_directories(dir);
    remove(dir / RESULT_NAME);

    const auto [name, count, flag, opt_flag, opt_name] = load_result_default<TestEntry>(dir);
    CHECK_EQ(name,  "");   // no result.json → Entry{} not entry_default
    CHECK_EQ(count, 0);
    CHECK_EQ(flag,  false);
    CHECK_FALSE(opt_flag.has_value());
    CHECK_FALSE(opt_name.has_value());
}