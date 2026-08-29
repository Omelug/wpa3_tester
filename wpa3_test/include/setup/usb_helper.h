#pragma once
#include <filesystem>
#include <string>
#include <vector>

namespace wpa3_tester{

struct UsbResetInfo {
	std::filesystem::path auth_file;
	std::string iface_id;    // USB interface id, e.g. "2-1.3:1.0"
	std::string driver_name; // e.g. "mt76x2u"
};

// Scans /sys/class/ieee80211/ for USB-backed WiFi phys.
// Covers all cfg80211 drivers: mac80211 and out-of-tree
// only misses pre-cfg80211 WEXT-only drivers (effectively extinct).
std::vector<UsbResetInfo> collect_all_usb_wifi_ifaces();
void reset_usb_ifaces();
void reset_usb_ifaces(const std::vector<UsbResetInfo>& ifaces);

}
