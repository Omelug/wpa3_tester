#pragma once
#include <filesystem>
#include <string>
#include <vector>

namespace wpa3_tester{

struct UsbResetInfo {
	std::filesystem::path dev_path;  // e.g. /sys/bus/usb/devices/1-1.4.4.3
	std::string iface_id;            // e.g. "1-1.4.4.3"
	std::string driver_name;         // e.g. "mt76x2u"
};

// Scans /sys/class/ieee80211/ for USB-backed WiFi phys.
// Covers all cfg80211 drivers: mac80211 and out-of-tree
// only misses pre-cfg80211 WEXT-only drivers (effectively extinct).
std::vector<UsbResetInfo> collect_all_usb_wifi_ifaces();
void reset_usb_ifaces();

}
