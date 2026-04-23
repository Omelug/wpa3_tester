#pragma once

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

nl80211_iftype query_wifi_iftype(std::string_view iface_name);

[[nodiscard]] bool iface_is_up(std::string_view iface_name);
[[nodiscard]] bool iface_is_down(std::string_view iface_name);

[[nodiscard]] Result wait_for_link_flags(std::string_view iface_name, bool want_up, int timeout_ms = 5000);
[[nodiscard]] Result wait_for_iface_disappear(std::string_view iface_name);
[[nodiscard]] Result wait_for_iface_appear(std::string_view iface_name, int timeout_ms = 5000);
[[nodiscard]] Result wait_for_wifi_iftype(std::string_view iface_name,
                                          nl80211_iftype expected_type,
                                          int max_retries = 50,
                                          int retry_ms = 100
);
void log_iface_info(std::string_view iface_name);
} // namespace wpa3_tester::netlink_helper
