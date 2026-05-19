#include <sys/wait.h>
#include <vector>
#include <random>

#include "ex_program/external_actors/ExternalConn.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester{
using namespace std;

void Actor_config::set_channel(const Channel ch, const string &ht_mode) const{
	const string &iface = get(SK::iface);
	if(conn != nullptr){ conn->set_channel(iface, ch, ht_mode); return; }
	hw_capabilities::set_channel(iface, ch, (*this)[SK::netns]);
}

bool is_interface_up(const string &iface){
	ifstream status_file("/sys/class/net/" + iface + "/operstate");
	string status;
	if(status_file >> status){ return (status == "up"); }
	return false;
}

void Actor_config::cleanup() const{
	string iface = get(SK::iface);
	const optional<string> netns = (*this)[SK::netns];
	if(iface.empty()){
		log(LogLevel::ERROR, "cleanup() called with empty interface name");
		return;
	}

	if(netns.has_value()){
		hw_capabilities::move_to_netns(iface, netns.value());
	} else{
		log(LogLevel::INFO, "Cleaning up interface {}", iface);
	}

	run({"pkill", "-f", "tshark.*" + iface}, false);
	run({"pkill", "-f", "tcpdump.*" + iface}, false);

	run({"rm", "-f", "/var/run/wpa_supplicant/" + iface});
	if((*this)[SK::sniff_iface].has_value()){
		run({"iw", "dev", get(SK::sniff_iface), "del"});

		run({"pkill", "-f", "wpa_supplicant.*-i" + iface}, false);
		run({"pkill", "-f", "hostapd.*" + iface}, false);

		set_iface_down();
		run({"rfkill", "unblock", "wifi"});
	}
	run({"ip", "addr", "flush", "dev", iface});
	set_iface_up();
}

void Actor_config::create_sniff_iface() const{
	const string &iface = get(SK::iface);
	const string &sniff_iface = get(SK::sniff_iface);
	if(conn != nullptr){
		throw not_implemented_err("External cant have sniff_iface");
		//conn->create_sniff_iface(iface, sniff_iface); return;
	}

	if(run({"ip", "link", "show", sniff_iface}) == 0){
		log(LogLevel::INFO, "Sniff interface {} already exists. Setting UP.", sniff_iface);
		set_iface_up();
		return;
	}

	log(LogLevel::DEBUG, "Interface {} not found, creating new one.", sniff_iface);
	const auto fd_count = distance(filesystem::directory_iterator("/proc/self/fd"), filesystem::directory_iterator{});
	log(LogLevel::DEBUG, "Current open FDs: %ld {} {}", fd_count, iface, sniff_iface.c_str());

	string monitor_flags;
	vector<string> cmd = {
		"iw", "dev", iface, "interface", "add", sniff_iface, "type", "monitor", "flags", "fcsfail", "otherbss"
	};
	if((*this)[BK::active_monitor]) cmd.emplace_back("active");
	if((*this)[BK::control_monitor]) cmd.emplace_back("control");
	run(cmd);
	set_iface_up();
}

//------------------ get status info functions

void Actor_config::set_ap_mode() const{
	const string &iface = get(SK::iface);
	log(LogLevel::INFO, "Preparing interface {} for AP mode", iface);

	set_iface_down();
	run({"iw", "dev", iface, "set", "type", "__ap"});
	//run({"ip", "addr", "add", "192.168.1.1/24", "dev", iface});
}

void Actor_config::up_sniff_iface() const{
	if(!(*this)[SK::sniff_iface].has_value()) return;
	const string &sniff_iface = get(SK::sniff_iface);

	if(is_interface_up(sniff_iface)){
		log(LogLevel::DEBUG, "{} is already UP, skipping.", sniff_iface);
		return;
	}
	log(LogLevel::INFO, "Bringing {} UP...", sniff_iface);
	run({"ip", "link", "set", sniff_iface, "up"});
}

void Actor_config::set_managed_mode() const{
	const string &iface = get(SK::iface);
	if(conn != nullptr){ conn->set_managed_mode(iface); return; }
	const optional<string> netns = (*this)[SK::netns];

	log(LogLevel::INFO, "Preparing interface {} for managed mode", iface);
	set_iface_down();
	run({"iw", "dev", iface, "set", "type", "managed"});
}

void Actor_config::set_mac_address(const Tins::HWAddress<6> &mac) const{
	const string &iface = get(SK::iface);
	if(conn != nullptr){ throw not_implemented_err("not valid for external "); }
	hw_capabilities::set_mac_address(iface, mac, (*this)[SK::netns]);

	if((*this)[SK::sniff_iface].has_value()){
		hw_capabilities::set_mac_address(get(SK::sniff_iface), mac, (*this)[SK::netns]);
	}
}

void Actor_config::set_monitor_mode() const{
	const string &iface = get(SK::iface);
	if(conn != nullptr){ conn->set_monitor_mode(iface); return; }

	vector<string> monitor_flags = {"fcsfail", "otherbss"};
	if((*this)[BK::active_monitor]) monitor_flags.push_back("active");
	if((*this)[BK::control_monitor]) monitor_flags.push_back("control");

	string flags_str;
	for(const auto &f : monitor_flags){ if(!flags_str.empty()) flags_str += ' '; flags_str += f; }
	log(LogLevel::INFO, "Setting interface {} to monitor mode with flags {}", iface, flags_str);

	set_iface_down();
	set_wifi_type(NL80211_IFTYPE_MONITOR, monitor_flags);
}

// -------- hw_capabilities wrappers

int Actor_config::run(const vector<string> &argv, const bool print) const{
	return hw_capabilities::run_cmd(argv, (*this)[SK::netns], print);
}

string Actor_config::get_driver_name() const{
	return hw_capabilities::get_driver_name(get(SK::iface));
}

void Actor_config::set_iface_down() const{
	hw_capabilities::set_iface_down(get(SK::iface), (*this)[SK::netns]);
}

void Actor_config::set_iface_up() const{
	hw_capabilities::set_iface_up(get(SK::iface), (*this)[SK::netns]);
}

void Actor_config::set_wifi_type(const nl80211_iftype type, const vector<string> &monitor_flags) const{
	hw_capabilities::set_wifi_type(get(SK::iface), type, (*this)[SK::netns], monitor_flags);
}
}