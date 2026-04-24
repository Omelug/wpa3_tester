#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <string>
#include <stdexcept>

#include "logger/error_log.h"
#include "logger/log.h"

using namespace std;
using namespace wpa3_tester;

TEST_CASE("config_err - simple string message"){
    try {
        throw config_err("Simple error message");
    } catch (const config_err& e) {
        CHECK(string(e.what()) == "Simple error message");
    }
}

TEST_CASE("config_err - formatted message with single argument"){
    try {
        throw config_err("Config not found: %s", "/path/to/config.yaml");
    } catch (const config_err& e) {
        CHECK(string(e.what()) == "Config not found: /path/to/config.yaml");
    }
}

TEST_CASE("config_err - formatted message with multiple arguments"){
    try {
        throw config_err("Error at line %d in file %s: %s", 42, "config.yaml", "invalid syntax");
    } catch (const config_err& e) {
        CHECK(string(e.what()) == "Error at line 42 in file config.yaml: invalid syntax");
    }
}

TEST_CASE("config_err - string + string"){
    try {
        const string& t = "line 42";
        throw config_err("Error at "+t);
    } catch (const config_err& e) {
        CHECK(string(e.what()) == "Error at line 42");
    }
}

TEST_CASE("config_err - formatted message with c_str()"){
    const string path = "/some/path/to/file";
    try {
        throw config_err("Path "+path+" has no valid name");
    } catch (const config_err& e) {
        CHECK(string(e.what()) == "Path /some/path/to/file has no valid name");
    }
}