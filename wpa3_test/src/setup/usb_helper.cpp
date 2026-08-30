#include "setup/usb_helper.h"
#include "config/Observer_config.h"
#include "config/RunStatus.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "interrupt.h"
#include "system/hw_capabilities.h"
#include <chrono>
#include <fcntl.h>
#include <filesystem>
#include <linux/usbdevice_fs.h>
#include <sys/ioctl.h>
#include <vector>
#include <future>

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
		const path& dev_path = entry.path();
		const string name = dev_path.filename().string();

		// skip interface nodes (e.g. "1-1.2:1.0")
		if (name.find(':') != string::npos)
			continue;
		// skip virtual root hubs ("usb1", "usb2", ...) — they have
		// an "authorized" file too but aren't real devices to reset
		if (name.rfind("usb", 0) == 0)
			continue;

		const path auth_file = dev_path / "authorized";
		if (!exists(auth_file))
			continue;

		// only keep devices that actually expose a wifi interface,
		// so hubs themselves (e.g. "1-1") get excluded too
		bool is_wifi = false;
		string driver_name = "unknown";
		for (const auto &sub_e : directory_iterator(dev_path)) {
			if (sub_e.path().filename().string().find(':') != string::npos) {
				path drv_link = sub_e.path() / "driver";
				if (is_symlink(drv_link))
					driver_name = canonical(drv_link).filename().string();
				if (exists(sub_e.path() / "net") || exists(sub_e.path() / "ieee80211"))
					is_wifi = true;
			}
		}
		if (!is_wifi)
			continue;

		result.push_back({auth_file, name, driver_name});
	}
	return result;
}

static size_t count_usb_wifi_phys(){
	const path ieee80211 = "/sys/class/ieee80211";
	if(!exists(ieee80211)) return 0;
	size_t n = 0;
	for(const auto &phy_e: directory_iterator(ieee80211)){
		if(!is_symlink(phy_e.path())) continue;
		const path dev_link = phy_e.path() / "device";
		if(!exists(dev_link)) continue;
		const string iface_id = canonical(dev_link).filename().string();
		if(iface_id.find(':') != string::npos) ++n;
	}
	return n;
}

// add manual test
void reset_usb_ifaces(){
	reset_usb_ifaces(collect_all_usb_wifi_ifaces());
}

static bool hard_reset_usb_device(const path& sysfs_auth_file) {
	path dev_dir = sysfs_auth_file.parent_path();

	ifstream bus_file(dev_dir / "busnum");
	ifstream dev_file(dev_dir / "devnum");

	int busnum = -1, devnum = -1;
	if (!(bus_file >> busnum) || !(dev_file >> devnum)) return false;

	char dev_path[64];
	snprintf(dev_path, sizeof(dev_path), "/dev/bus/usb/%03d/%03d", busnum, devnum);

	int fd = open(dev_path, O_WRONLY);
	if (fd < 0) return false;

	int rc = ioctl(fd, USBDEVFS_RESET, 0);
	close(fd);

	return rc >= 0;
}

void reset_usb_ifaces(const vector<UsbResetInfo> &ifaces) {
	if (ifaces.empty()) return;

	set<string> root_hubs;
	for (const auto &info : ifaces) {
		const string dev_name = info.auth_file.parent_path().filename().string();
		const size_t first_dot = dev_name.find('.');
		if (first_dot != string::npos)
			root_hubs.insert(dev_name.substr(0, first_dot));
		else
			root_hubs.insert(dev_name);
	}
	auto t0 = chrono::steady_clock::now();
	hw_capabilities::run_cmd({"modprobe", "-r", "ath9k_htc"}, nullopt, false);
	auto t1 = chrono::steady_clock::now();
	log(LogLevel::INFO, "modprobe -r: {}ms", chrono::duration_cast<chrono::milliseconds>(t1-t0).count());


	// parallelize reset of hubs and check of success
	bool uhubctl_success = false;
	{
		vector<future<int>> futures;
		futures.reserve(root_hubs.size());
		for (const auto &hub : root_hubs) {
			futures.push_back(async(launch::async, [&hub]() {
				return hw_capabilities::run_cmd({"uhubctl", "-a", "cycle", "-l", hub}, nullopt, false);
			}));
		}
		for (auto &f : futures) {
			if (f.get() == 0) uhubctl_success = true;
		}
	}

	if (!uhubctl_success) {
		vector<future<void>> futures;
		futures.reserve(ifaces.size());
		for (const auto &info : ifaces) {
			futures.push_back(async(launch::async, [&info]() {
				if (!hard_reset_usb_device(info.auth_file))
					log(LogLevel::WARNING, "USB ioctl reset failed for {} — needs root or udev rule for /dev/bus/usb",
						info.auth_file.string());
			}));
		}
		for (auto &f : futures) f.get();
	}

	auto t2 = chrono::steady_clock::now();
	log(LogLevel::INFO, "uhubctl cycle: {}ms", chrono::duration_cast<chrono::milliseconds>(t2-t1).count());

	interruptible_sleep(chrono::milliseconds(200));
	auto t3 = chrono::steady_clock::now();
	hw_capabilities::run_cmd({"modprobe", "ath9k_htc"}, nullopt, false);
	auto t4 = chrono::steady_clock::now();
	log(LogLevel::INFO, "modprobe insert: {}ms", chrono::duration_cast<chrono::milliseconds>(t4-t3).count());


	// wait for firmware to finish loading async
	const size_t expected = ifaces.size();
	const auto phy_deadline = chrono::steady_clock::now() + chrono::seconds(20);
	while(chrono::steady_clock::now() < phy_deadline && !g_interrupted.load()){
		if(count_usb_wifi_phys() >= expected) break;
		interruptible_sleep(chrono::milliseconds(100));
	}
	auto t5 = chrono::steady_clock::now();
	log(LogLevel::INFO, "wait for phys: {}ms", chrono::duration_cast<chrono::milliseconds>(t5-t4).count());

}

}
