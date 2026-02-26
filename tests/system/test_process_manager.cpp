#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <thread>
#include <chrono>
#include <doctest/doctest.h>

#include "logger/log.h"
#include "system/ProcessManager.h"

using namespace std;
using namespace filesystem;
using namespace wpa3_tester;
using namespace std::chrono_literals;

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
            CHECK((pm.processes.contains("test_proc")));
            this_thread::sleep_for(500ms);

            pm.stop("test_proc");
            CHECK((!pm.processes.contains("test_proc")));
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

        CHECK((pm.processes.size() == 3));
        CHECK((pm.processes.contains("test_proc1")));
        CHECK((pm.processes.contains("test_proc2")));
        CHECK((pm.processes.contains("test_proc3")));

        this_thread::sleep_for(100ms);
        pm.stop_all();

        CHECK(pm.processes.empty());

        log(LogLevel::INFO, "stop_all test completed successfully");
        //remove_all(test_dir);
    }

    TEST_CASE("ProcessManager - stop_all handles empty process list") {
        ProcessManager pm;

        const auto test_dir = temp_directory_path() / "pm_test_empty";
        create_directories(test_dir);
        pm.init_logging(test_dir.string());

        CHECK_NOTHROW(pm.stop_all());
        CHECK(pm.processes.empty());

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

        CHECK((pm.processes.size() == 2));

        this_thread::sleep_for(100ms);
        pm.stop("proc1");

        CHECK((pm.processes.size() == 1));
        CHECK((!pm.processes.contains("proc1")));
        CHECK((pm.processes.contains("proc2")));

        pm.stop_all();
        CHECK(pm.processes.empty());

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
}

