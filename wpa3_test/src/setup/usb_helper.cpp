#include "setup/usb_helper.h"
#include "config/Observer_config.h"
#include "config/RunStatus.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "interrupt.h"
#include "system/hw_capabilities.h"
#include <chrono>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>
#include <thread>
#include <vector>

using namespace std;
using namespace filesystem;
using nlohmann::json;

namespace wpa3_tester{

vector<UsbResetInfo> collect_all_usb_wifi_ifaces() {
	vector<UsbResetInfo> result;
	const path usb_devs = "/sys/bus/usb/devices";
	if (!exists(usb_devs))
		return result;

	for (const auto &entry : directory_iterator(usb_devs)) {
		const path &dev_path = entry.path();
		const string name = dev_path.filename().string();

		if (name.find(':') != string::npos)
			continue;
		if (name.rfind("usb", 0) == 0)
			continue;

		bool is_wifi = false;
		string driver_name = "unknown";
		for (const auto &sub_e : directory_iterator(dev_path)) {
			if (sub_e.path().filename().string().find(':') == string::npos)
				continue;
			path drv_link = sub_e.path() / "driver";
			if (is_symlink(drv_link))
				driver_name = canonical(drv_link).filename().string();
			if (driver_name == "hub")
				continue;
			is_wifi = true;
		}
		if (!is_wifi)
			continue;

		result.push_back({dev_path, name, driver_name});
	}
	return result;
}

void reset_usb_ifaces() {
	{
		ofstream f("/sys/bus/usb/drivers_autoprobe");
		f << "1";
	}

	// Unload wifi drivers before power cycle - prevents ath9k_htc ANI workqueue
	// from firing after USB disconnect but before driver cleanup.
	const auto wifi_ifaces = collect_all_usb_wifi_ifaces();
	size_t expected_with_driver = 0;
	set<string> drivers;
	for (const auto &iface : wifi_ifaces) {
		if (iface.driver_name != "unknown") {
			drivers.insert(iface.driver_name);
			++expected_with_driver;
		}
	}
	for (const auto &drv : drivers) {
		hw_capabilities::run_cmd({"modprobe", "-r", drv}, nullopt, false);
		log(LogLevel::DEBUG, "reset_usb_ifaces: unloaded driver {}", drv);
	}

	// Use uhubctl list to find hubs - independent of sysfs device state.
	// Devices may be absent from sysfs if stuck in kernel USB error-recovery.
	const string hub_list =
		hw_capabilities::run_cmd_output({"uhubctl"}, nullopt);
	const string prefix = "Current status for hub ";
	vector<string> locs;
	istringstream ss(hub_list);
	string line;
	while (getline(ss, line)) {
		if (line.rfind(prefix, 0) != 0)
			continue;
		string loc;
		istringstream(line.substr(prefix.size())) >> loc;
		if (loc.find('-') == string::npos)
			continue; // skip root hubs - no PPPS (Per-Port Power Switching)
		locs.push_back(loc);
	}
	if (locs.empty()) {
		log(LogLevel::WARNING, "reset_usb_ifaces: no switchable hubs found - reloading drivers without power cycle");
		for (const auto &drv : drivers)
			hw_capabilities::run_cmd({"modprobe", drv}, nullopt, false);
		hw_capabilities::run_cmd({"udevadm", "settle", "--timeout=10"}, nullopt, false);
		return;
	}

	// split off/on into two invocations - uhubctl -a cycle hangs on power-on
	// because the libusb handle opened before the delay goes stale.
	for (const auto &loc : locs) {
		hw_capabilities::run_cmd({"uhubctl", "-l", loc, "-a", "off"}, nullopt, false);
		log(LogLevel::INFO, "reset_usb_ifaces: powered off hub {}", loc);
	}
	this_thread::sleep_for(chrono::seconds(3));
	for (const auto &loc : locs) {
		hw_capabilities::run_cmd({"uhubctl", "-l", loc, "-a", "on"}, nullopt, false);
		log(LogLevel::INFO, "reset_usb_ifaces: powered on hub {}", loc);
	}

	// Poll until all adapters have drivers bound. ath9k_htc firmware upload can
	// take 40+ seconds - a fixed sleep is not enough.
	if (expected_with_driver > 0) {
		const auto deadline = chrono::steady_clock::now() + chrono::seconds(60);
		while (chrono::steady_clock::now() < deadline) {
			const auto current = collect_all_usb_wifi_ifaces();
			size_t ready = 0;
			for (const auto &i : current)
				if (i.driver_name != "unknown") ++ready;
			if (ready >= expected_with_driver) break;
			log(LogLevel::DEBUG, "reset_usb_ifaces: {}/{} adapters ready, waiting...", ready, expected_with_driver);
			this_thread::sleep_for(chrono::seconds(3));
		}
	} else {
		// fallback when no adapters were in sysfs before reset
		this_thread::sleep_for(chrono::seconds(8));
	}
	hw_capabilities::run_cmd({"udevadm", "settle", "--timeout=10"}, nullopt, false);
}

}
