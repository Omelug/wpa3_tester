#pragma once

#include <nlohmann/json.hpp>
#include <nlohmann/json_fwd.hpp>
#include <string>

namespace wpa3_tester::driver_diag{

// collects best-effort driver-specific diagnostics from debugfs for
// drivers groups: (mt76, rtw88, rtw89, ath9k_htc, rtl8xxxu)

// ABI stability NOT guarantee
// there are no stability constraints placed on files exported there
// https://docs.kernel.org/filesystems/debugfs.html
nlohmann::json collect_driver_specific(const std::string &driver_name, const std::string &phy);
std::string summarize_driver_specific(const nlohmann::json &driver_specific);

// regulatory domain from iw + ieee80211 debugfs
nlohmann::json collect_regulatory(const std::string &phy,
								  const std::optional<std::string> &netns);

// USB device info (vendor, product, serial) read from sysfs; nullopt fields when not USB
nlohmann::json collect_usb_info(const std::string &iface);

}