#pragma once

#include <expected>
#include <string_view>
#include <system_error>
#include <linux/nl80211.h>

namespace wpa3_tester::netlink_helper {

    using Result = std::expected<void, std::error_code>;

    [[nodiscard]] int    open_rtnetlink();

    [[nodiscard]] Result wait_for_link_flags  (int nl_fd, std::string_view iface_name, bool want_up);
    [[nodiscard]] Result wait_for_iface_appear(int nl_fd, std::string_view iface_name);
    [[nodiscard]] Result wait_for_wifi_iftype (std::string_view iface_name,
                                               nl80211_iftype expected_type,
                                               int max_retries = 50,
                                               int retry_ms    = 100);

} // namespace wpa3_tester::netlink_helper