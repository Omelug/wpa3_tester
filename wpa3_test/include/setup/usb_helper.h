#pragma once
#include <filesystem>
#include <string>
#include <vector>

namespace wpa3_tester {

struct UsbResetInfo {
	std::filesystem::path dev_path; // e.g. /sys/bus/usb/devices/1-1.4.4.3
	std::string iface_id;			// e.g. "1-1.4.4.3"
	std::string driver_name;		// e.g. "mt76x2u"
	std::string vendor_id;			// e.g. "0cf3"
	std::string product_id;			// e.g. "9271"
};

std::vector<UsbResetInfo> collect_all_usb_devices();
void usb_bus_reset(const std::vector<UsbResetInfo> &devs);
void reset_usb_ifaces();

}
