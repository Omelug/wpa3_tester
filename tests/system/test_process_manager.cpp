#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <filesystem>
#include <thread>
#include <chrono>
#include "system/ProcessManager.h"
#include "logger/log.h"

using namespace std;
using namespace wpa3_tester;
using namespace std::chrono_literals;

namespace wpa3_tester {
    TEST_CASE("ProcessManager - stop_all handles multiple processes") {
        ProcessManager pm;

        const auto test_dir = filesystem::temp_directory_path() / "pm_test_stop_all";
        filesystem::create_directories(test_dir);

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
        filesystem::remove_all(test_dir);
    }

    TEST_CASE("ProcessManager - stop_all handles empty process list") {
        ProcessManager pm;

        const auto test_dir = filesystem::temp_directory_path() / "pm_test_empty";
        filesystem::create_directories(test_dir);
        pm.init_logging(test_dir.string());

        CHECK_NOTHROW(pm.stop_all());
        CHECK(pm.processes.empty());

        log(LogLevel::INFO, "stop_all empty test completed successfully");
        filesystem::remove_all(test_dir);
    }

    TEST_CASE("ProcessManager - stop individual process") {
        ProcessManager pm;

        const auto test_dir = filesystem::temp_directory_path() / "pm_test_stop_one";
        filesystem::create_directories(test_dir);
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
        filesystem::remove_all(test_dir);
    }

    TEST_CASE("ProcessManager - stop nonexistent process") {
        ProcessManager pm;

        const auto test_dir = filesystem::temp_directory_path() / "pm_test_nonexistent";
        filesystem::create_directories(test_dir);
        pm.init_logging(test_dir.string());

        CHECK_NOTHROW(pm.stop("nonexistent_process"));

        log(LogLevel::INFO, "stop nonexistent process test completed successfully");
        filesystem::remove_all(test_dir);
    }

    TEST_CASE("ProcessManager - process logging") {
        ProcessManager pm;

        const auto test_dir = filesystem::temp_directory_path() / "pm_test_logging";
        filesystem::create_directories(test_dir);
        pm.init_logging(test_dir.string());

        vector<string> echo_cmd = {"echo", "test output"};
        pm.run("echo_test", echo_cmd);

        this_thread::sleep_for(500ms);

        const auto log_file = pm.log_base_dir / "echo_test.log";
        CHECK(filesystem::exists(log_file));

        const auto combined_log = pm.log_base_dir / "combined.log";
        CHECK(filesystem::exists(combined_log));

        pm.stop_all();
        log(LogLevel::INFO, "process logging test completed successfully");
        filesystem::remove_all(test_dir);
    }
}

