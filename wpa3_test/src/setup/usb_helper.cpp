#include <algorithm>
#include <chrono>
#include <filesystem>
#include <ranges>
#include <vector>
#include "setup/usb_helper.h"
#include "interrupt.h"
#include "config/Observer_config.h"
#include "config/RunStatus.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "system/hw_capabilities.h"

using namespace std;
using namespace filesystem;
using nlohmann::json;

namespace wpa3_tester{

// Scan /sys/class/ieee80211/ — every cfg80211 driver (mac80211 or direct) registers
// a phy here, including out-of-tree drivers like rtl8812au. Both this path and
// /sys/bus/usb/ are not network-namespaced, so interfaces in any namespace are visible.
// Only misses pre-cfg80211 WEXT-only drivers (effectively extinct).
vector<UsbResetInfo> collect_all_usb_wifi_ifaces(){
	vector<UsbResetInfo> result;
	const path ieee80211 = "/sys/class/ieee80211";
	if(!exists(ieee80211)) return result;

	for(const auto &phy_e: directory_iterator(ieee80211)){
		if(!is_symlink(phy_e.path())) continue;

		// phy device symlink points to the USB interface sysfs dir (e.g. .../2-1.3:1.0)
		const path dev_link = phy_e.path() / "device";
		if(!exists(dev_link)) continue;
		const path usb_iface_path = canonical(dev_link);

		// USB interface dirs have a ':' in the last path component
		const string iface_id = usb_iface_path.filename().string();
		if(iface_id.find(':') == string::npos) continue;

		const path drv_link = usb_iface_path / "driver";
		if(!is_symlink(drv_link)) continue;
		const string driver_name = canonical(drv_link).filename().string();

		path auth_file;
		for(path p = usb_iface_path.parent_path(); p != p.root_path(); p = p.parent_path()){
			if(exists(p / "authorized")){ auth_file = p / "authorized"; break; }
		}
		if(auth_file.empty()) continue;

		result.push_back({auth_file, iface_id, driver_name});
	}
	return result;
}

path get_usb_auth_path(const string& iface_name) {
	const path sysfs_path = path("/sys/class/net") / iface_name / "device";
	if (!exists(sysfs_path)) return "";

	const path real_path = canonical(sysfs_path);
	for (auto p = real_path; p != p.root_path(); p = p.parent_path()) {
		if (exists(p / "authorized")) {
			return p / "authorized";
		}
	}
	return "";
}

void disconnect_usb_device(const string& iface_name) {
	const path auth_file = get_usb_auth_path(iface_name);
	if (auth_file.empty()) return;
	ofstream out(auth_file);
	if (out) out << "0";
}

void connect_usb_device(const path& auth_file) {
	if(auth_file.empty()) return;
	ofstream out(auth_file);
	if(out) out << "1";
}

void connect_usb_device(const string& iface_name) {
	connect_usb_device(get_usb_auth_path(iface_name));
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

}

// add manual test
void reset_usb_ifaces(){
	do_usb_reset(collect_all_usb_wifi_ifaces());
}

void reset_usb_ifaces(const vector<UsbResetInfo> &ifaces){
	do_usb_reset(ifaces);
}
}
