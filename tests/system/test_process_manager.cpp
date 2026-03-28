#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <thread>
#include <chrono>
#include "logger/log.h"
#include "logger/error_log.h"
#include "system/ProcessManager.h"

using namespace std;
using namespace filesystem;
using namespace wpa3_tester;
using namespace chrono_literals;

namespace wpa3_tester {
    TEST_CASE("ProcessManager run and stop simple process"){
        {
            ProcessManager pm;
            vector<string> cmd = {"sleep","150"};
            const auto test_dir = temp_directory_path() / "pm_test_stop_all";
            create_directories(test_dir);
            pm.init_logging(test_dir.string());

            pm.run("test_proc", cmd);
            this_thread::sleep_for(500ms);
            CHECK((pm.process_exists("test_proc")));
            this_thread::sleep_for(500ms);

            pm.stop("test_proc");
            CHECK((!pm.process_exists("test_proc")));
        }
        CHECK(true);
    }

    TEST_CASE("ProcessManager - stop_all handles multiple processes") {

        ProcessManager pm;

        const auto test_dir = temp_directory_path() / "pm_test_stop_all";
        create_directories(test_dir);

        pm.init_logging(test_dir.string());

        vector<string> sleep_cmd1 = {"sleep", "300"};
        vector<string> sleep_cmd2 = {"sleep", "300"};
        vector<string> sleep_cmd3 = {"sleep", "300"};

        pm.run("test_proc1", sleep_cmd1);
        pm.run("test_proc2", sleep_cmd2);
        pm.run("test_proc3", sleep_cmd3);

        CHECK((pm.processes_size() == 3));
        CHECK((pm.process_exists("test_proc1")));
        CHECK((pm.process_exists("test_proc2")));
        CHECK((pm.process_exists("test_proc3")));

        this_thread::sleep_for(chrono::milliseconds(500));
        pm.stop_all();

        CHECK((pm.processes_size() == 0));

        log(LogLevel::INFO, "stop_all test completed successfully");
        //remove_all(test_dir);
    }

    TEST_CASE("ProcessManager - stop_all handles empty process list") {
        ProcessManager pm;

        const auto test_dir = temp_directory_path() / "pm_test_empty";
        create_directories(test_dir);
        pm.init_logging(test_dir.string());

        CHECK_NOTHROW(pm.stop_all());
        CHECK((pm.processes_size() == 0));

        log(LogLevel::INFO, "stop_all empty test completed successfully");
        remove_all(test_dir);
    }

    TEST_CASE("ProcessManager - stop individual process"){
        const auto test_dir = temp_directory_path() / "pm_test_stop_one";
        ProcessManager pm;
        create_directories(test_dir);
        pm.init_logging(test_dir.string());

        vector<string> sleep_cmd1 = {"sleep", "300"};
        vector<string> sleep_cmd2 = {"sleep", "300"};

        pm.run("proc1", sleep_cmd1);
        pm.run("proc2", sleep_cmd2);

        CHECK((pm.processes_size() == 2));

        this_thread::sleep_for(100ms);
        pm.stop("proc1");

        CHECK((pm.processes_size() == 1));
        CHECK((!pm.process_exists("proc1")));
        CHECK((pm.process_exists("proc2")));

        pm.stop_all();
        CHECK((pm.processes_size() == 0));

        log(LogLevel::INFO, "stop individual process test completed successfully");
        remove_all(test_dir);
    }

    TEST_CASE("ProcessManager - stop nonexistent process") {
        ProcessManager pm;

        const auto test_dir = temp_directory_path() / "pm_test_nonexistent";
        create_directories(test_dir);
        pm.init_logging(test_dir.string());

        CHECK_NOTHROW(pm.stop("nonexistent_process"));

        log(LogLevel::INFO, "stop nonexistent process test completed successfully");
        remove_all(test_dir);
    }

    TEST_CASE("ProcessManager - process logging") {
        ProcessManager pm;

        const auto test_dir = temp_directory_path() / "pm_test_logging";
        create_directories(test_dir);
        pm.init_logging(test_dir.string());

        vector<string> echo_cmd = {"echo", "test output"};
        pm.run("echo_test", echo_cmd);

        this_thread::sleep_for(500ms);

        const auto log_file = pm.log_base_dir / "echo_test.log";
        CHECK(exists(log_file));

        const auto combined_log = pm.log_base_dir / "combined.log";
        CHECK(exists(combined_log));

        pm.stop_all();
        log(LogLevel::INFO, "process logging test completed successfully");
        //remove_all(test_dir);
    }

    TEST_CASE("ProcessManager - wait_for with timeout") {
        ProcessManager pm;

        const auto test_dir = temp_directory_path() / "pm_test_wait_timeout";
        create_directories(test_dir);
        pm.init_logging(test_dir.string());

        SUBCASE("Pattern found within timeout") {
            vector<string> echo_cmd = {"bash", "-c", "echo 'test pattern'; sleep 5"};
            pm.run("echo_test", echo_cmd);

            pm.allow_history("echo_test");
            this_thread::sleep_for(200ms);

            CHECK_NOTHROW(pm.wait_for("echo_test", "test pattern", 5s));
            pm.stop("echo_test");
        }

        SUBCASE("Timeout waiting for pattern") {
            vector<string> sleep_cmd = {"sleep", "10"};
            pm.run("sleep_test", sleep_cmd);

            pm.allow_history("sleep_test");

            CHECK_THROWS_AS(pm.wait_for("sleep_test", "never_appears", 2s), timeout_err);
            pm.stop("sleep_test");
        }

        SUBCASE("Custom short timeout") {
            vector<string> sleep_cmd = {"sleep", "10"};
            pm.run("short_timeout", sleep_cmd);

            pm.allow_history("short_timeout");

            auto start = chrono::steady_clock::now();
            CHECK_THROWS_AS(pm.wait_for("short_timeout", "not_found", 1s), timeout_err);
            auto duration = chrono::steady_clock::now() - start;

            CHECK((duration >= 1s));
            CHECK((duration < 2s));

            pm.stop("short_timeout");
        }

        pm.stop_all();
        log(LogLevel::INFO, "wait_for timeout test completed successfully");
        remove_all(test_dir);
    }

    TEST_CASE("ProcessManager - on_stop callback") {
        ProcessManager pm;

        const auto test_dir = temp_directory_path() / "pm_test_on_stop";
        create_directories(test_dir);
        pm.init_logging(test_dir.string());

        vector<string> sleep_cmd = {"sleep", "300"};
        pm.run("test_proc", sleep_cmd);

        bool callback_called = false;
        pm.on_stop("test_proc", [&callback_called]() {
            callback_called = true;
        });

        this_thread::sleep_for(100ms);
        pm.stop("test_proc");

        CHECK(callback_called);

        log(LogLevel::INFO, "on_stop callback test completed successfully");
        remove_all(test_dir);
    }
}
