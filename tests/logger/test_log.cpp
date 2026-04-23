#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <ctime>
#include <cstdint>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>

#include "config/RunStatus.h"
#include "logger/log.h"

using namespace std;
using wpa3_tester::LogTimePoint;

TEST_CASE (
"log - debug message with actor name"
)
 {
    const string actor_name = "test_actor";
    const string expected_message = "DEBUG: Created and registered ExternalConn for actor: "+actor_name;

    // Redirect stderr to capture log output
    ostringstream captured_output;
    streambuf* original_cerr = cerr.rdbuf(captured_output.rdbuf());

    wpa3_tester::log(wpa3_tester::LogLevel::DEBUG, "Created and registered ExternalConn for actor: "+actor_name);

    // Restore original cerr
    cerr.rdbuf(original_cerr);

    CHECK_NE(captured_output.str().find(expected_message), string::npos);
}