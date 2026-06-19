#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <tins/tins.h>
#include "config/Actor_Config/actor_keys.h"
#include "logger/log.h"

using namespace std;
using wpa3_tester::LogTimePoint;

TEST_CASE("log - debug message with actor name"){
    const string actor_name = "test_actor";
    const string expected_message = "DEBUG: Created and registered ExternalConn for actor: "+actor_name;

    // Redirect stderr to capture log output
    ostringstream captured_output;
    streambuf* original_cerr = cerr.rdbuf(captured_output.rdbuf());

    wpa3_tester::log(wpa3_tester::LogLevel::DEBUG, "Created and registered ExternalConn for actor: {}", actor_name);

    // Restore original cerr
    cerr.rdbuf(original_cerr);

    CHECK_NE(captured_output.str().find(expected_message), string::npos);
}

TEST_CASE("log - set_log_file writes messages to file"){
    const filesystem::path tmp = "/tmp/wpa3_test_log.txt";
    filesystem::remove(tmp);

    wpa3_tester::set_log_file(tmp);
    wpa3_tester::log(wpa3_tester::LogLevel::INFO, "file_log_test");
    wpa3_tester::set_log_file("");  // close

    ifstream f(tmp);
    const string content((istreambuf_iterator(f)), istreambuf_iterator<char>());
    filesystem::remove(tmp);

    CHECK_NE(content.find("file_log_test"), string::npos);
}

TEST_CASE("log - log_actor_map prints name and keys"){
    wpa3_tester::ActorCMap m;
    m["alpha"] = wpa3_tester::ActorPtr{};
    m["beta"]  = wpa3_tester::ActorPtr{};

    ostringstream captured;
    streambuf* orig = cerr.rdbuf(captured.rdbuf());
    wpa3_tester::log_actor_map("my_map", m);
    cerr.rdbuf(orig);

    const string out = captured.str();
    CHECK_NE(out.find("my_map:"), string::npos);
    CHECK_NE(out.find("alpha"), string::npos);
    CHECK_NE(out.find("beta"), string::npos);
}

TEST_CASE("formatter - Tins::HWAddress formats as string"){
    const Tins::HWAddress<6> addr("aa:bb:cc:dd:ee:ff");
    CHECK_EQ(format("{}", addr), addr.to_string());
    CHECK_EQ(format("mac={}", Tins::HWAddress<6>("00:11:22:33:44:55")), "mac=00:11:22:33:44:55");
}

TEST_CASE("formatter - filesystem::path formats as string"){
    const filesystem::path p = "/tmp/some/path.txt";
    CHECK_EQ(format("{}", p), p.string());
    CHECK_EQ(format("prefix/{}", filesystem::path("foo/bar")), "prefix/foo/bar");
}

TEST_CASE("log - escape_tex replaces underscores"){
    CHECK_EQ(wpa3_tester::escape_tex("hello_world"),   "hello\\_world");
    CHECK_EQ(wpa3_tester::escape_tex("a_b_c"),         "a\\_b\\_c");
    CHECK_EQ(wpa3_tester::escape_tex("no underscores"), "no underscores");
}