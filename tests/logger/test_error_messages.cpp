#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <stdexcept>
#include <string>
#include <thread>

#include "logger/error_log.h"
#include "logger/log.h"

using namespace std;
using namespace wpa3_tester;

TEST_CASE("config_err - simple string message") {
	try {
		throw config_err("Simple error message");
	} catch(const config_err &e) { CHECK_EQ(string(e.what()), "Simple error message"); }
}

TEST_CASE("config_err - formatted message with single argument") {
	try {
		throw config_err("Config not found: {}", "/path/to/config.yaml");
	} catch(const config_err &e) { CHECK_EQ(string(e.what()), "Config not found: /path/to/config.yaml"); }
}

TEST_CASE("config_err - formatted message with multiple arguments") {
	try {
		throw config_err("Error at line {} in file {}: {}", 42, "config.yaml", "invalid syntax");
	} catch(const config_err &e) { CHECK_EQ(string(e.what()), "Error at line 42 in file config.yaml: invalid syntax"); }
}

TEST_CASE("config_err - string + string") {
	try {
		const string &t = "line 42";
		throw config_err("Error at " + t);
	} catch(const config_err &e) { CHECK_EQ(string(e.what()), "Error at line 42"); }
}

TEST_CASE("config_err - formatted message with c_str()") {
	const string path = "/some/path/to/file";
	try {
		throw config_err("Path " + path + " has no valid name");
	} catch(const config_err &e) { CHECK_EQ(string(e.what()), "Path /some/path/to/file has no valid name"); }
}

// -----------------
// throw_trace_for
// -----------------

// Verifies that __wrap___cxa_throw records a stacktrace for plain std::exceptions.
// Catches the regression where only tester_error had a trace and foreign exceptions
// (e.g. Tins::malformed_packet) produced an empty "Stacktrace:" section in errors.txt.
TEST_CASE("throw_trace_for - same-thread throw yields non-empty trace") {
	try {
		throw runtime_error("boom");
	} catch(const exception &e) {
		CHECK_FALSE(throw_trace_for(&e).empty());
	}
}

// Verifies the thread_local  global-mutex fix in throw_trace.cpp.
// Before the fix, an exception thrown in a worker thread stored its trace in that
// thread's thread_local map; the main thread's throw_trace_for() saw an empty map
// and returned an empty stacktrace, so errors.txt showed "Stacktrace:" with nothing.
TEST_CASE("throw_trace_for - cross-thread throw visible from catching thread") {
	exception_ptr ep;
	thread([&ep] {
		try { throw runtime_error("worker boom"); }
		catch(...) { ep = current_exception(); }
	}).join();

	REQUIRE(ep);
	try {
		rethrow_exception(ep);
	} catch(const exception &e) {
		CHECK_FALSE(throw_trace_for(&e).empty());
	}
}

// Guards against false positives: a pointer that was never thrown must not
// accidentally map to a stale entry left by a previous exception at the same address.
TEST_CASE("throw_trace_for - unknown pointer returns empty trace") {
	const runtime_error e("not thrown");
	CHECK(throw_trace_for(&e).empty());
}