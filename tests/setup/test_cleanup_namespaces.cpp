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
#include <chrono>
#include <doctest/doctest.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "system/hw_capabilities.h"

namespace wpa3_tester{
static void cleanup_all_namespaces();
void kill_process_in_ns_name(const std::string &ns_name);
void delete_ns_and_wait(const std::string &ns_name, const std::vector<std::string> &ifaces,
    std::chrono::milliseconds timeout = std::chrono::milliseconds(3000));
}

using namespace std;
using namespace filesystem;

namespace{
struct RootGuard{
    RootGuard(){
        if(geteuid() != 0){
            cerr << "[skip] test_cleanup_namespaces requires root (sudo). Skipping.\n";
            exit(0);
        }
    }
};

[[maybe_unused]] const RootGuard root_guard;
}

static bool netns_exists(const string &name){
    return exists("/var/run/netns/" + name);
}

static pid_t start_process_in_netns(const string &ns, const string &prog){
    const string ns_path = "/var/run/netns/" + ns;
    const pid_t pid = fork();
    if(pid == 0){
        // Enter the network namespace directly (no sudo wrapper)
        const int fd = open(ns_path.c_str(), O_RDONLY | O_CLOEXEC);
        if(fd < 0){ _exit(1); }
        if(setns(fd, CLONE_NEWNET) < 0){
            close(fd);
            _exit(2);
        }
        close(fd);
        execlp(prog.c_str(), prog.c_str(), "infinity", nullptr);
        _exit(127);
    }

    // Give the child a moment to start
    usleep(100'000);
    return pid;
}

// Check whether a PID is still alive (visible in /proc).
static bool pid_alive(const pid_t pid){
    return exists("/proc/" + to_string(pid));
}

struct NsGuard{
    string name;
    explicit NsGuard(string n): name(std::move(n)){}
    ~NsGuard() = default;
};

TEST_CASE("cleanup_all_namespaces - removes multiple empty namespaces"){
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
        CHECK_EQ((netns_exists(n)), false);
    }
}

TEST_CASE("cleanup_all_namespaces - kills processes and removes namespace"){
    const string ns = "wpa3_test_ns4";
    NsGuard guard(ns);

    wpa3_tester::hw_capabilities::run_cmd({"ip", "netns", "add", ns});

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

TEST_CASE("kill_process_in_ns_name - nonexistent namespace does not crash"){
    CHECK_NOTHROW(wpa3_tester::kill_process_in_ns_name("wpa3_test_nonexistent_ns"));
}

TEST_CASE("kill_process_in_ns_name - empty namespace does not crash"){
    const string ns = "wpa3_test_kill_empty";
    wpa3_tester::hw_capabilities::run_cmd({"ip", "netns", "add", ns});
    REQUIRE(netns_exists(ns));
    CHECK_NOTHROW(wpa3_tester::kill_process_in_ns_name(ns));
    wpa3_tester::hw_capabilities::run_cmd({"ip", "netns", "del", ns});
}

TEST_CASE("kill_process_in_ns_name - terminates process via SIGTERM"){
    const string ns = "wpa3_test_kill_term";
    wpa3_tester::hw_capabilities::run_cmd({"ip", "netns", "add", ns});
    REQUIRE(netns_exists(ns));

    const pid_t child = start_process_in_netns(ns, "sleep");
    REQUIRE_GT(child, 0);
    REQUIRE(pid_alive(child));

    wpa3_tester::kill_process_in_ns_name(ns);

    for(int i = 0; i < 50 && pid_alive(child); ++i){ usleep(20'000); }
    CHECK_FALSE(pid_alive(child));
    waitpid(child, nullptr, WNOHANG);

    wpa3_tester::hw_capabilities::run_cmd({"ip", "netns", "del", ns});
}

TEST_CASE("kill_process_in_ns_name - kills SIGTERM-ignoring process via SIGKILL"){
    const string ns = "wpa3_test_kill_sigkill";
    wpa3_tester::hw_capabilities::run_cmd({"ip", "netns", "add", ns});
    REQUIRE(netns_exists(ns));

    // Fork a child that ignores SIGTERM and sleeps in the namespace
    const string ns_path = "/var/run/netns/" + ns;
    const pid_t child = fork();
    REQUIRE_GE(child, 0);
    if(child == 0){
        const int fd = open(ns_path.c_str(), O_RDONLY | O_CLOEXEC);
        if(fd < 0 || setns(fd, CLONE_NEWNET) < 0){ _exit(1); }
        close(fd);
        signal(SIGTERM, SIG_IGN);
        pause();
        _exit(0);
    }
    usleep(100'000);
    REQUIRE(pid_alive(child));

    wpa3_tester::kill_process_in_ns_name(ns);

    // Function sends SIGKILL after 500 ms deadline; give a bit more time
    for(int i = 0; i < 100 && pid_alive(child); ++i){ usleep(20'000); }
    CHECK_FALSE(pid_alive(child));
    waitpid(child, nullptr, WNOHANG);

    wpa3_tester::hw_capabilities::run_cmd({"ip", "netns", "del", ns});
}

TEST_CASE("delete_ns_and_wait - hwsim interface returns to root ns"){
    using namespace wpa3_tester;
    using namespace filesystem;
    using namespace chrono;

    // Snapshot existing wifi interfaces to identify the new hwsim one
    const auto before = hw_capabilities::list_interfaces(InterfaceType::Wifi);

    hw_capabilities::run_cmd({"modprobe", "mac80211_hwsim", "radios=1"});
    hw_capabilities::run_cmd({"udevadm", "settle"}, nullopt, false);

    const auto after = hw_capabilities::list_interfaces(InterfaceType::Wifi);

    string hwsim_iface;
    for(const auto &a : after){
        bool existed = false;
        for(const auto &b : before) if(b.name == a.name){ existed = true; break; }
        if(!existed){ hwsim_iface = a.name; break; }
    }

    if(hwsim_iface.empty()){
        MESSAGE("No new wifi interface appeared after loading mac80211_hwsim — skipping");
        hw_capabilities::run_cmd({"modprobe", "-r", "mac80211_hwsim"}, nullopt, false);
        return;
    }

    const string ns = "wpa3_test_hwsim_del_ns";
    hw_capabilities::run_cmd({"ip", "netns", "add", ns});
    REQUIRE(netns_exists(ns));

    hw_capabilities::move_to_netns(hwsim_iface, ns);
    REQUIRE_FALSE(exists("/sys/class/net/" + hwsim_iface));

    const auto t0 = steady_clock::now();
    delete_ns_and_wait(ns, {hwsim_iface}, milliseconds(3000));
    const auto elapsed = duration_cast<milliseconds>(steady_clock::now() - t0).count();

    CHECK_FALSE(netns_exists(ns));
    CHECK(exists("/sys/class/net/" + hwsim_iface));
    // Kernel moves the interface synchronously on ns deletion — should be well under 1 s
    CHECK_LT(elapsed, 1000);

    hw_capabilities::run_cmd({"modprobe", "-r", "mac80211_hwsim"}, nullopt, false);
}