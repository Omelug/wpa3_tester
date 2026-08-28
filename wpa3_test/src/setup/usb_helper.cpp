#include "setup/usb_helper.h"
#include "config/Observer_config.h"
#include "config/RunStatus.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "interrupt.h"
#include "system/hw_capabilities.h"
#include <chrono>
#include <filesystem>
#include <linux/usbdevice_fs.h>
#include <sys/ioctl.h>
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
		const path dev_path = entry.path();

		// only USB devices (not : in name)
		const string name = dev_path.filename().string();
		if (name.find(':') != string::npos)
			continue;

		// file 'authorized' are only for physical interfaces
		const path auth_file = dev_path / "authorized";
		if (!exists(auth_file))
			continue;

		string driver_name = "unknown";

		// get driver (not important for reset) //TODO needed?
		for (const auto &sub_e : directory_iterator(dev_path)) {
			if (sub_e.path().filename().string().find(':') != string::npos) {
				path drv_link = sub_e.path() / "driver";
				if (is_symlink(drv_link)) {
					driver_name = canonical(drv_link).filename().string();
					break;
				}
			}
		}

		// doesnt matter if have driver
		result.push_back({auth_file, name, driver_name});
	}
	return result;
}

path get_usb_auth_path(const string &iface_name) {
	const path sysfs_path = path("/sys/class/net") / iface_name / "device";
	if (!exists(sysfs_path))
		return "";

	const path real_path = canonical(sysfs_path);
	for (auto p = real_path; p != p.root_path(); p = p.parent_path()) {
		if (exists(p / "authorized")) {
			return p / "authorized";
		}
	}
	return "";
}

void disconnect_usb_device(const string &iface_name) {
	const path auth_file = get_usb_auth_path(iface_name);
	if (auth_file.empty())
		return;
	ofstream out(auth_file);
	if (out)
		out << "0";
}

void connect_usb_device(const string &iface_name) {
	connect_usb_device(get_usb_auth_path(iface_name));
}

void connect_usb_device(const path &auth_file) {
	if (auth_file.empty())
		return;
	ofstream out(auth_file);
	if (out)
		out << "1";
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

static void do_usb_reset(const vector<UsbResetInfo> &ifaces){
	// disconnect
	for(const auto &info: ifaces){
		ofstream out(info.auth_file);
		if(out) out << "0";
	}

	interruptible_sleep(chrono::milliseconds(500)); //FIXME hardcoded

	// reconnect: re-authorize (triggers USB enumeration + driver auto-probe)
	for(const auto &info: ifaces){ connect_usb_device(info.auth_file); }

	hw_capabilities::run_cmd({"modprobe", "ath9k_htc"}, nullopt, false); //FIXME make generic

	// rebind interfaces that didn't auto-probe after re-authorization
	// in a namespace; writing the interface id to the driver's bind file forces a new probe
	const auto bind_deadline = chrono::steady_clock::now() + chrono::seconds(10); //FIXME hardcoded
	while(chrono::steady_clock::now() < bind_deadline && !g_interrupted.load()){
		bool all_bound = true;
		for(const auto &[auth_file, iface_id, drv_name]: ifaces){
			if(is_symlink(auth_file.parent_path() / iface_id / "driver")) continue;
			all_bound = false;
			const path bind = path("/sys/bus/usb/drivers") / drv_name / "bind";
			if(!exists(bind)) continue;
			ofstream out(bind);
			if(out) out << iface_id;
		}
		if(all_bound) break;
		interruptible_sleep(chrono::milliseconds(500)); //FIXME hardcoded
	}

	// retry auth for devices still not bound — ath9k_htc on some hubs gets
	// -110 (SET_CONFIGURATION timeout) on the first auth cycle and needs a second attempt
	// with a longer disconnect to let the device's USB controller settle.
	vector<size_t> retry_idx;
	for(size_t i = 0; i < ifaces.size(); ++i){
		const auto &[auth_file, iface_id, drv_name] = ifaces[i];
		if(!is_symlink(auth_file.parent_path() / iface_id / "driver"))
			retry_idx.push_back(i);
	}
	if(!retry_idx.empty()){
		for(size_t i: retry_idx){ ofstream out(ifaces[i].auth_file); if(out) out << "0"; }
		interruptible_sleep(chrono::milliseconds(1000)); //TODO why this time?
		for(size_t i: retry_idx){ ofstream out(ifaces[i].auth_file); if(out) out << "1"; }
	}

	// driver symlink appears at probe() start, but ath9k_htc loads firmware async —
	// the phy only appears in ieee80211 after firmware completes
	const size_t expected = ifaces.size();
	const auto phy_deadline = chrono::steady_clock::now() + chrono::seconds(20);
	while(chrono::steady_clock::now() < phy_deadline && !g_interrupted.load()){
		if(count_usb_wifi_phys() >= expected) break;
		interruptible_sleep(chrono::milliseconds(500));
	}
}

// add manual test
void reset_usb_ifaces(){
	do_usb_reset(collect_all_usb_wifi_ifaces());
}

static bool hard_reset_usb_device(const path& sysfs_auth_file) {
	// sysfs_auth_file je např. /sys/bus/usb/devices/1-1.1.3/authorized
	path dev_dir = sysfs_auth_file.parent_path();

	ifstream bus_file(dev_dir / "busnum");
	ifstream dev_file(dev_dir / "devnum");

	int busnum = -1, devnum = -1;
	if (!(bus_file >> busnum) || !(dev_file >> devnum)) return false;

	// devfs path: /dev/bus/usb/001/003
	char dev_path[64];
	snprintf(dev_path, sizeof(dev_path), "/dev/bus/usb/%03d/%03d", busnum, devnum);

	int fd = open(dev_path, O_WRONLY);
	if (fd < 0) return false;

	// USB RESET
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
		if (first_dot != string::npos) {
			root_hubs.insert(dev_name.substr(0, first_dot));
		} else {
			root_hubs.insert(dev_name);
		}
	}

	// set drivers down
	hw_capabilities::run_cmd({"modprobe", "-r", "ath9k_htc"}, nullopt, false);

	bool uhubctl_success = false;
	for (const auto &hub : root_hubs) {
		const int res = hw_capabilities::run_cmd({"uhubctl", "-a", "cycle", "-l", hub}, nullopt, false);
		if (res == 0) uhubctl_success = true;
	}

	if (!uhubctl_success) { // hub cant power of with uhubctl
		for (const auto &info : ifaces) {
			hard_reset_usb_device(info.auth_file);
		}
	}

	interruptible_sleep(chrono::milliseconds(200)); //TODO why this time?

	// setup drivers up
	hw_capabilities::run_cmd({"modprobe", "ath9k_htc"}, nullopt, false);
}

}
