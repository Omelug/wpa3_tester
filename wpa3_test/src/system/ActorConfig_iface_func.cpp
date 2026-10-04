#include <random>
#include <vector>
#include <sys/wait.h>

#include "ex_program/external_actors/ExternalConn.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester{
using namespace std;


void Actor_config::cleanup() const{
	string iface = get(SK::iface);
	const optional<string> netns = (*this)[SK::netns];
	if(iface.empty()){
		log(LogLevel::ERROR, "cleanup() called with empty interface name");
		return;
	}

	if(netns.has_value()){
		if((*this)[BK::netns_change]) throw run_err("netns_change not allowed");
		hw_capabilities::move_to_netns(iface, netns.value());
	} else{
		log(LogLevel::INFO, "Cleaning up interface {}", iface);
	}

	//TODO needed?
	hw_capabilities::pkill_wait("tshark.*" + iface);
	hw_capabilities::pkill_wait("tcpdump.*" + iface);
	hw_capabilities::pkill_wait("dnsmasq.*" + iface);
	hw_capabilities::pkill_wait("wpa_supplicant.*-i" + iface);
	hw_capabilities::pkill_wait("hostapd.*" + iface);

	run({"rm", "-f", "/var/run/wpa_supplicant/" + iface});
	if((*this)[BK::sniff_iface].has_value() && (*this)[BK::sniff_iface].value() == true){ // proč to závisí na
		run({"iw", "dev", get_mon_iface(), "del"}, false);
		hw_capabilities::pkill_wait("wpa_supplicant.*" + get_mon_iface());
		hw_capabilities::pkill_wait("hostapd.*" + get_mon_iface());
		set_iface_down();
	}
	run({"rfkill", "unblock", "wifi"});
	set_iface_down(); // cycle DOWN to flush nl80211 frame registrations
	if(const auto perm = (*this)[SK::permanent_mac]; perm.has_value())
		hw_capabilities::set_mac_address(iface, Tins::HWAddress<6>(perm.value()), (*this)[SK::netns]);
	run({"ip", "addr", "flush", "dev", iface});
	set_iface_up();
}

void Actor_config::create_sniff_iface() const{
	const string &iface = get(SK::iface);
	const string &sniff_iface = get_mon_iface();
	if(conn != nullptr){
		conn->create_sniff_iface(iface, sniff_iface);
		throw not_implemented_err("External cant have sniff_iface");
	}

	if(run({"ip", "link", "show", sniff_iface}, false) == 0){
		log(LogLevel::INFO, "Sniff interface {} already exists", sniff_iface);
		return;
	}

	log(LogLevel::DEBUG, "Creating new sniff interface {}", sniff_iface);
	const auto fd_count = distance(filesystem::directory_iterator("/proc/self/fd"), filesystem::directory_iterator{});
	log(LogLevel::DEBUG, "Current open FDs: {} {} {}", fd_count, iface, sniff_iface.c_str());

	// add VIF
	run({"iw", "dev", iface, "interface", "add", sniff_iface, "type", "monitor"});

	vector<string> flags_cmd = {"iw", "dev", sniff_iface, "set", "monitor", "fcsfail", "otherbss"};
	if(get_or(BK::active_monitor, false)) flags_cmd.emplace_back("active");
	if(get_or(BK::control_monitor, false)) flags_cmd.emplace_back("control");
	run(flags_cmd);
}

void Actor_config::set_channel(const Channel &ch) const{
	const string &iface = get(SK::iface);
	if(conn != nullptr){
		conn->set_channel(iface, ch);
		return;
	}
	hw_capabilities::set_channel(iface, ch, (*this)[SK::netns]);
}

//------------------ get status info functions

void Actor_config::set_ap_mode() const{
	if(conn != nullptr){
		throw not_implemented_err("configured with uci for now on openwrt");
	}
	const string &iface = get(SK::iface);
	log(LogLevel::INFO, "Preparing interface {} for AP mode", iface);
	set_iface_down();
	set_wifi_type(NL80211_IFTYPE_AP, {});
}

void Actor_config::up_sniff_iface() const{
	hw_capabilities::set_iface_up(get_mon_iface(), (*this)[SK::netns]);
}

void Actor_config::set_managed_mode() const{
	const string &iface = get(SK::iface);
	if(conn != nullptr){
		conn->set_managed_mode(iface);
		return;
	}
	const optional<string> netns = (*this)[SK::netns];

	log(LogLevel::INFO, "Preparing interface {} for managed mode", iface);
	set_iface_down();
	run({"iw", "dev", iface, "set", "type", "managed"});
}

void Actor_config::set_mac_address(const Tins::HWAddress<6> &mac) const{
	const string &iface = get(SK::iface);
	if(conn != nullptr) {
		throw not_implemented_err("not valid for external ");
	}
	hw_capabilities::set_mac_address(iface, mac, (*this)[SK::netns]);

	if((*this)[BK::sniff_iface]){
		const string mon = get_mon_iface();
		if(run({"ip", "link", "show", mon}, false) == 0)
			hw_capabilities::set_mac_address(mon, mac, (*this)[SK::netns]);
	}
}

void Actor_config::set_monitor_mode(const bool add_flags) const{
	const string &iface = get(SK::iface);
	if(conn != nullptr){
		conn->set_monitor_mode(iface);
		return;
	}

	//TODO not in deal fcsfail (issues for parsing, but important for injection debugging)
	vector<string> monitor_flags = {"fcsfail", "otherbss"};

	if (add_flags) {
		if(get_or(BK::active_monitor, false)) monitor_flags.emplace_back("active");
		if(get_or(BK::control_monitor, false)) monitor_flags.emplace_back("control");
	}
	string flags_str = join(monitor_flags, " ");
	log(LogLevel::INFO, "Setting interface {} to monitor mode with flags {}", iface, flags_str);

	set_iface_down();
	set_wifi_type(NL80211_IFTYPE_MONITOR, monitor_flags);
}

// -------- hw_capabilities wrappers

int Actor_config::run(const vector<string> &argv, const bool print) const{
	return hw_capabilities::run_cmd(argv, (*this)[SK::netns], print);
}

string Actor_config::get_driver_name() const{
	return hw_capabilities::get_driver_name(get(SK::iface), (*this)[SK::netns]);
}

void Actor_config::set_iface_down() const{
	hw_capabilities::set_iface_down(get(SK::iface), (*this)[SK::netns]);
}

void Actor_config::set_iface_up() const{
	if(conn != nullptr){
		conn->set_iface_up(get(SK::iface));
		return;
	}
	hw_capabilities::set_iface_up(get(SK::iface), (*this)[SK::netns]);
}

void Actor_config::set_wifi_type(const nl80211_iftype type, const vector<string> &monitor_flags) const{
	hw_capabilities::set_wifi_type(get(SK::iface), type, (*this)[SK::netns], monitor_flags);
}
}