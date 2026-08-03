#include <chrono>
#include <filesystem>
#include <vector>

#include "interrupt.h"
#include "config/Observer_config.h"
#include "config/RunStatus.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "system/hw_capabilities.h"

using namespace std;
using namespace filesystem;
using nlohmann::json;

namespace wpa3_tester{

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

void reset_usb_ifaces(){
	vector<pair<string, path>> reset_targets;
	for(const auto &[iface_name, radio, type]: hw_capabilities::list_interfaces(InterfaceType::Wifi, nullopt)){
		const path auth_file = get_usb_auth_path(iface_name);
		if(auth_file.empty()) continue;
		reset_targets.emplace_back(iface_name, auth_file);
	}

	for(const auto &auth_file: reset_targets | views::values) {
		connect_usb_device(auth_file);
	}

	interruptible_sleep(chrono::milliseconds(500));

	for(const auto &auth_file: reset_targets | views::values) {
		ofstream out(auth_file);
		if(out) {
			out << "1";
		}
	}

	hw_capabilities::run_cmd({"modprobe", "ath9k_htc"}, nullopt, false); //FIXME make generic

	vector<string> waiting;
	for(const auto &iface_name: reset_targets | views::keys)
		waiting.push_back(iface_name);

	int retries = 100; // max 10 secs (100 * 100ms)
	while(!waiting.empty() && retries > 0 && !g_interrupted.load()){
		interruptible_sleep(chrono::milliseconds(100));
		retries--;
		waiting.erase(
			ranges::remove_if(waiting, [](const string &iface){
				return exists(path("/sys/class/net") / iface);
			}).begin(),
			waiting.end()
		);
	}
	interruptible_sleep(chrono::milliseconds(5000));
}

}