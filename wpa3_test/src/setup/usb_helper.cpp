#include "setup/usb_helper.h"
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>
#include <thread>
#include <vector>
#include "config/Observer_config.h"
#include "config/RunStatus.h"
#include "config/global_config.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "interrupt.h"
#include "system/hw_capabilities.h"

using namespace std;
using namespace filesystem;
using nlohmann::json;

namespace wpa3_tester {

namespace {

vector<string> find_switchable_hubs() {
	const string out = hw_capabilities::run_cmd_output({ "uhubctl" }, nullopt);
	const string prefix = "Current status for hub ";
	vector<string> locs;
	istringstream ss(out);
	string line;
	while(getline(ss, line)) {
		if(line.rfind(prefix, 0) != 0) continue;
		string loc;
		istringstream(line.substr(prefix.size())) >> loc;
		if(loc.find('-') != string::npos) // root hubs have no '-', no PPPS
			locs.push_back(loc);
	}
	return locs;
}

}

void usb_bus_reset(const vector<UsbResetInfo> &devs) {
	for(const auto &dev: devs) {
		ofstream f(dev.dev_path / "reset");
		if(f) f << "1";
		log(LogLevel::DEBUG, "reset_usb_ifaces: USB reset {}", dev.iface_id);
	}
}

vector<UsbResetInfo> collect_all_usb_devices() {
	vector<UsbResetInfo> result;
	const path usb_devs = "/sys/bus/usb/devices";
	if(!exists(usb_devs)) return result;

	for(const auto &entry: directory_iterator(usb_devs)) {
		const path &dev_path = entry.path();
		const string name = dev_path.filename().string();

		if(name.find(':') != string::npos) continue;
		if(name.rfind("usb", 0) == 0) continue;

		bool is_device = false;
		string driver_name = "unknown";
		for(const auto &sub_e: directory_iterator(dev_path)) {
			if(sub_e.path().filename().string().find(':') == string::npos) continue;
			path drv_link = sub_e.path() / "driver";
			if(is_symlink(drv_link)) driver_name = canonical(drv_link).filename().string();
			if(driver_name == "hub") continue;
			is_device = true;
		}
		if(!is_device) continue;

		auto read_line = [](const path &p) { ifstream f(p); string s; if(f) getline(f, s); return s; };
		result.push_back({ dev_path, name, driver_name,
			read_line(dev_path / "idVendor"),
			read_line(dev_path / "idProduct")
		});
	}
	return result;
}

void reset_usb_ifaces() {
	{
		ofstream f("/sys/bus/usb/drivers_autoprobe");
		f << "1";
	}

	// Unload Wi-Fi drivers before power cycle - prevents ath9k_htc ANI workqueue
	// from firing after USB disconnect but before driver cleanup.
	auto wifi_ifaces = collect_all_usb_devices();

	auto &cfg = get_global_config();
	if(cfg.contains("only_list_reset")) {
		const auto raw = cfg.at("only_list_reset").get<vector<string>>();
		if(!raw.empty()) {
			set<string> allowed;
			for(const auto &s: raw) {
				string lc = s;
				ranges::transform(lc, lc.begin(), ::tolower);
				allowed.insert(lc);
			}
			const size_t total = wifi_ifaces.size();
			erase_if(wifi_ifaces, [&](const UsbResetInfo &d) {
				return !allowed.contains(d.vendor_id + ":" + d.product_id);
			});
			log(LogLevel::DEBUG, "reset_usb_ifaces: only_list_reset active, {}/{} devices match",
				wifi_ifaces.size(), total);
		}
	}
	set<string> drivers;
	for(const auto &iface: wifi_ifaces) {
		if(iface.driver_name != "unknown")
			drivers.insert(iface.driver_name);
	}
	const size_t expected_with_driver = wifi_ifaces.size();
	for(const auto &drv: drivers) {
		hw_capabilities::run_cmd({ "modprobe", "-r", drv }, nullopt, false);
		log(LogLevel::DEBUG, "reset_usb_ifaces: unloaded driver {}", drv);
	}
	hw_capabilities::run_cmd({ "udevadm", "settle", "--timeout=10" }, nullopt, false);

	const auto hubs = find_switchable_hubs();

	if(hubs.empty()) {
		log(LogLevel::WARNING, "reset_usb_ifaces: no switchable hubs found - reset drivers without power cycle");
		usb_bus_reset(wifi_ifaces);
		hw_capabilities::run_cmd({ "udevadm", "settle", "--timeout=10" }, nullopt, false);
	} else {

		// USB bus reset for devices not on any switchable hub (won't get power cycled)
		vector<UsbResetInfo> non_hub;
		for(const auto &dev: wifi_ifaces) {
			bool covered = ranges::any_of(hubs, [&](const string &loc) {
				return dev.iface_id.rfind(loc + ".", 0) == 0;
			});
			if(!covered) non_hub.push_back(dev);
		}
		if(!non_hub.empty()) usb_bus_reset(non_hub);

		// split off/on into two invocations - uhubctl -a cycle hangs on power-on
		// because the libusb handle opened before the delay goes stale.
		for(const auto &loc: hubs) {
			hw_capabilities::run_cmd({ "uhubctl", "-l", loc, "-a", "off" }, nullopt, false);
			log(LogLevel::INFO, "reset_usb_ifaces: powered off hub {}", loc);
		}
		interruptible_sleep(chrono::seconds(3));
		for(const auto &loc: hubs) {
			hw_capabilities::run_cmd({ "uhubctl", "-l", loc, "-a", "on" }, nullopt, false);
			log(LogLevel::INFO, "reset_usb_ifaces: powered on hub {}", loc);
		}
	}

	// modprobe is a no-op if already loaded; ensures non-hub adapters get driver bound
	for(const auto &drv: drivers) hw_capabilities::run_cmd({ "modprobe", drv }, nullopt, false);

	// wait until all adapters have drivers bound AND net interface exists in sysfs
	// Driver bind happens before firmware upload (ath9k_htc)
	// - checking net/ subdir is driver-agnostic and catches the firmware-upload gap
	auto has_netdev = [](const UsbResetInfo &d) {
		for(const auto &sub: directory_iterator(d.dev_path)) {
			if(sub.path().filename().string().find(':') == string::npos) continue;
			if(exists(sub.path() / "net")) return true;
		}
		return false;
	};
	if(expected_with_driver > 0) {
		const auto deadline = chrono::steady_clock::now() + chrono::seconds(60);
		while(chrono::steady_clock::now() < deadline) {
			const auto current = collect_all_usb_devices();
			const size_t net_ready = ranges::count_if(current, [&](const auto &i) {
				return i.driver_name != "unknown" && has_netdev(i);
			});
			if(net_ready >= expected_with_driver) break;
			log(LogLevel::DEBUG, "reset_usb_ifaces: {}/{} adapters net-ready, waiting...", net_ready, expected_with_driver);
			interruptible_sleep(chrono::seconds(3));
		}
	} else {
		log(LogLevel::WARNING, "Reset USB fallback");
		interruptible_sleep(chrono::seconds(8)); // fallback when no adapters were in sysfs before reset
	}
	hw_capabilities::run_cmd({ "udevadm", "settle", "--timeout=10" }, nullopt, false);
}

}
