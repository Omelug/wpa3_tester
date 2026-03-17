#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <cstdlib>
#include <utility>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <doctest/doctest.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "system/hw_capabilities.h"

namespace wpa3_tester { void cleanup_all_namespaces(); }
using namespace std;
using namespace filesystem;

namespace {
    struct RootGuard {
        RootGuard() {
            if (geteuid() != 0) {
                cerr << "[skip] test_cleanup_namespaces requires root (sudo). Skipping.\n";
                exit(0);
            }
        }
    };
    [[maybe_unused]] const RootGuard root_guard;
}

static bool netns_exists(const string& name) {
    return exists("/var/run/netns/"+name);
}

static pid_t start_process_in_netns(const string& ns, const string& prog) {
    const string ns_path = "/var/run/netns/"+ns;
    const pid_t pid = fork();
    if (pid == 0) {
        // Enter the network namespace directly (no sudo wrapper)
        const int fd = open(ns_path.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) { _exit(1); }
        if (setns(fd, CLONE_NEWNET) < 0) { close(fd); _exit(2); }
        close(fd);
        execlp(prog.c_str(), prog.c_str(), "infinity", nullptr);
        _exit(127);
    }

    // Give the child a moment to start
    usleep(100'000);
    return pid;
}

// Check whether a PID is still alive (visible in /proc).
static bool pid_alive(const pid_t pid) {
    return exists("/proc/"+to_string(pid));
}

struct NsGuard {
    string name;
    explicit NsGuard(string  n) : name(std::move(n)) {}
    ~NsGuard() = default;
};

TEST_CASE("cleanup_all_namespaces - removes multiple empty namespaces") {
    const vector<string> names = {"wpa3_test_ns1", "wpa3_test_ns2", "wpa3_test_ns3"};
    vector<NsGuard> guards;
    for (const auto& n : names) {
        guards.emplace_back(n);
        REQUIRE_NOTHROW(wpa3_tester::hw_capabilities::create_ns(n));
    }
    CHECK(netns_exists("wpa3_test_ns1"));
    CHECK(netns_exists("wpa3_test_ns2"));
    CHECK(netns_exists("wpa3_test_ns3"));
    wpa3_tester::cleanup_all_namespaces();

    for (const auto& n : names){
        CHECK_FALSE(netns_exists(n));
    }
}

TEST_CASE("cleanup_all_namespaces - kills processes and removes namespace") {
    const string ns = "wpa3_test_ns4";
    NsGuard guard(ns);

    wpa3_tester::hw_capabilities::run_cmd({"sudo", "ip", "netns", "add", ns});

    pid_t child = start_process_in_netns(ns, "sleep");
    REQUIRE((child > 0));
    REQUIRE(pid_alive(child));

    wpa3_tester::cleanup_all_namespaces();

    CHECK_FALSE(netns_exists(ns));

    for (int i = 0; i < 100 && pid_alive(child); ++i) { usleep(20'000); }
    if (pid_alive(child)) { kill(child, SIGKILL); usleep(50'000); }

    INFO(child);
    CHECK_FALSE(pid_alive(child));
    waitpid(child, nullptr, WNOHANG);
}

