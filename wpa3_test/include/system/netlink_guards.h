#pragma once
#include <memory>
#include <mutex>
#include <optional>
#include <unistd.h>
#include <unordered_map>
#include <bits/basic_string.h>

namespace wpa3_tester::netlink_helper{

struct SockGuard{
    int fd;
    explicit SockGuard(const int fd): fd{fd}{}
    ~SockGuard(){ if(fd >= 0) close(fd); }
    SockGuard(const SockGuard &) = delete;
    SockGuard &operator=(const SockGuard &) = delete;
};

struct NetNSContext {
    int old_ns_fd = -1;
    bool switched = false;
    explicit NetNSContext(const std::optional<std::string> &netns);
    ~NetNSContext();
};

class NetlinkRegistry {
public:
    static int get_fd(const std::optional<std::string>& netns);
private:
    static std::mutex& get_mutex();
    static std::unordered_map<std::string, std::unique_ptr<SockGuard>> &get_cache();
};
}
