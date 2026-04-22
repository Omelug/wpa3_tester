#pragma once
#include <expected>
#include <nl80211.h>
#include <string_view>
#include <system_error>

namespace wpa3_tester::netlink_helper {

    // Opens a NETLINK_ROUTE socket subscribed to RTMGRP_LINK multicast group.
    // Returns the file descriptor on success, -1 on error.
    [[nodiscard]] int open_rtnetlink();

    // Blocks until the interface named `iface_name` transitions to UP (want_up=true)
    // or DOWN (want_up=false), as reported by RTM_NEWLINK messages.
    // Returns 0 on success, -1 on recv error.
    [[nodiscard]] int wait_for_link_flags(int nl_fd, std::string_view iface_name, bool want_up);

    // Blocks until an RTM_NEWLINK message arrives carrying IFLA_IFNAME == iface_name.
    // Use this after `iw dev add` to confirm the new virtual interface is visible.
    // Returns 0 on success, -1 on recv error.
    [[nodiscard]] int wait_for_iface_appear(int nl_fd, const std::string_view iface_name);


    [[nodiscard]] std::expected<void, std::error_code> wait_for_wifi_iftype(std::string_view iface_name,
                                                                            nl80211_iftype expected_type,
                                                                            int max_retries = 50,
                                                                            int retry_ms = 100);

}
