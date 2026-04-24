#pragma once
#include <expected>
#include <string_view>
#include <system_error>
#include <linux/nl80211.h>

namespace wpa3_tester::netlink_helper{
using Result = std::expected<void,std::error_code>;

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
