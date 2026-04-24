#include "system/netlink_guards.h"

#include <fcntl.h>
#include <memory>
#include <unordered_map>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>

using namespace std;

namespace wpa3_tester::netlink_helper{
NetNSContext::NetNSContext(const optional<string>& netns) {
    if (!netns) return;

    old_ns_fd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
    const string ns_path = "/var/run/netns/" + *netns;
    const int new_ns_fd = open(ns_path.c_str(), O_RDONLY | O_CLOEXEC);

    if (new_ns_fd >= 0) {
        if (setns(new_ns_fd, CLONE_NEWNET) == 0) {
            switched = true;
        }
        close(new_ns_fd);
    }
}

NetNSContext::~NetNSContext() {
    if (switched && old_ns_fd >= 0) {
        setns(old_ns_fd, CLONE_NEWNET);
    }
    if (old_ns_fd >= 0) close(old_ns_fd);
}

int NetlinkRegistry::get_fd(const optional<string>& netns) {
    lock_guard lock(get_mutex());
    auto& cache = get_cache();
    const string key = netns.value_or("default");
    if (const auto it = cache.find(key); it != cache.end()) {
        return it->second->fd;
    }

    NetNSContext ns_guard(netns);
    int new_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

    if (new_fd < 0) return -1;

    sockaddr_nl sa{.nl_family = AF_NETLINK, .nl_groups = RTMGRP_LINK};
    if (bind(new_fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) < 0) {
        close(new_fd);
        return -1;
    }

    cache[key] = make_unique<SockGuard>(new_fd);
    return new_fd;
}
mutex& NetlinkRegistry::get_mutex() {
    static mutex mtx;
    return mtx;
}

unordered_map<string, unique_ptr<SockGuard>> &NetlinkRegistry::get_cache() {
    static unordered_map<string, unique_ptr<SockGuard>> cache;
    return cache;
}
}
