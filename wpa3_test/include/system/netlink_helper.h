#pragma once
#include <fcntl.h>
#include <expected>
#include <mutex>
#include <string_view>
#include <system_error>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/nl80211.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>

namespace wpa3_tester::netlink_helper{
using Result = std::expected<void,std::error_code>;

// RAII wrapper so nl is closed even if an exception is thrown mid-sequence
struct NlGuard{
    int fd;
    explicit NlGuard(const int fd): fd{fd}{}
    ~NlGuard(){ if(fd >= 0) close(fd); }
    NlGuard(const NlGuard &) = delete;
    NlGuard &operator=(const NlGuard &) = delete;
};

struct SockGuard{
    int fd;
    explicit SockGuard(const int fd): fd{fd}{}
    ~SockGuard(){ if(fd >= 0) close(fd); }
    SockGuard(const SockGuard &) = delete;
};

class NetlinkManager{
public:
    static int get_fd(){
        static NlGuard manager(open_netlink_socket());
        return manager.fd;
    }

    static std::mutex &get_mutex(){
        static std::mutex mtx;
        return mtx;
    }
private:
    static int open_netlink_socket(){
        const int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
        if(fd < 0) return -1;

        sockaddr_nl sa{};
        sa.nl_family = AF_NETLINK;
        sa.nl_groups = RTMGRP_LINK;

        if(bind(fd, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)) < 0){
            close(fd);
            return -1;
        }
        return fd;
    }
};

struct NetNSContext {
    int old_ns_fd = -1;
    bool switched = false;

    explicit NetNSContext(const std::optional<std::string>& netns) {
        if (!netns) return;

        old_ns_fd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
        const std::string ns_path = "/var/run/netns/" + *netns;
        const int new_ns_fd = open(ns_path.c_str(), O_RDONLY | O_CLOEXEC);

        if (new_ns_fd >= 0) {
            if (setns(new_ns_fd, CLONE_NEWNET) == 0) {
                switched = true;
            }
            close(new_ns_fd);
        }
    }

    ~NetNSContext() {
        if (switched && old_ns_fd >= 0) {
            setns(old_ns_fd, CLONE_NEWNET);
        }
        if (old_ns_fd >= 0) close(old_ns_fd);
    }
};

nl80211_iftype query_wifi_iftype(std::string_view iface_name, const std::optional<std::string> &netns);

[[nodiscard]] bool iface_is_up(std::string_view iface_name, const std::optional<std::string>& netns);
[[nodiscard]] bool iface_is_down(std::string_view iface_name, const std::optional<std::string>& netns);

[[nodiscard]] Result wait_for_link_flags(std::string_view iface_name, const std::optional<std::string>& netns,
    bool want_up, int timeout_ms = 5000);
[[nodiscard]] Result wait_for_iface_disappear(std::string_view iface_name,
     const std::optional<std::string>& netns);
[[nodiscard]] Result wait_for_iface_appear(std::string_view iface_name, const std::optional<std::string>& netns,
    int timeout_ms = 5000);
[[nodiscard]] Result wait_for_wifi_iftype(std::string_view iface_name,
                                          const std::optional<std::string>& netns,
                                          nl80211_iftype expected_type,
                                          int max_retries = 50,
                                          int retry_ms = 100
);
void log_iface_info(std::string_view iface_name);
} // namespace wpa3_tester::netlink_helper
