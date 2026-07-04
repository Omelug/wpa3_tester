#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <array>
#include <fcntl.h>
#include <unistd.h>
#include <doctest/doctest.h>
#include "system/netlink_guards.h"

using namespace wpa3_tester::netlink_helper;

namespace{
std::string current_netns_target(){
    std::array<char, 256> buf{};
    const ssize_t n = readlink("/proc/self/ns/net", buf.data(), buf.size() - 1);
    return n > 0 ? std::string(buf.data(), n) : std::string();
}
}

TEST_CASE("NetNSContext - nullopt is a no-op"){
    const NetNSContext ctx(std::nullopt);
    CHECK_FALSE(ctx.switched);
    CHECK_LT(ctx.old_ns_fd, 0);
}

TEST_CASE("NetNSContext - nonexistent netns does not crash and does not change namespace"){
    const std::string before = current_netns_target();
    {
        const NetNSContext ctx("this_netns_does_not_exist_xyz");
        CHECK_EQ(current_netns_target(), before);
    }
    CHECK_EQ(current_netns_target(), before);
}

TEST_CASE("SockGuard - closes fd on destruction"){
    const int fd = open("/dev/null", O_RDONLY);
    REQUIRE_GE(fd, 0);
    {
        const SockGuard guard(fd);
        CHECK_EQ(guard.fd, fd);
    }
    // fd should now be closed; using it should fail
    CHECK_LT(fcntl(fd, F_GETFD), 0);
}

TEST_CASE("NetlinkRegistry::get_fd - returns a valid, cached fd for the same netns key"){
    const int fd1 = NetlinkRegistry::get_fd(std::nullopt);
    REQUIRE_GE(fd1, 0);

    const int fd2 = NetlinkRegistry::get_fd(std::nullopt);
    CHECK_EQ(fd1, fd2);
}

TEST_CASE("NetlinkRegistry::get_fd - different netns keys get independent fds"){
    const int fd_default = NetlinkRegistry::get_fd(std::nullopt);
    const int fd_other = NetlinkRegistry::get_fd(std::string("this_netns_does_not_exist_xyz"));

    REQUIRE_GE(fd_default, 0);
    REQUIRE_GE(fd_other, 0);
    CHECK_NE(fd_default, fd_other);
}
