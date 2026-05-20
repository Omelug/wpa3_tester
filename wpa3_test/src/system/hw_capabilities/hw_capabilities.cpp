#include "system/hw_capabilities.h"
#include <cstdio>
#include <fstream>
#include <random>
#include <sstream>
#include <set>
#include <string>
#include <vector>
#include <reproc++/drain.hpp>
#include <sys/types.h>
#include <sys/wait.h>
#include "config/global_config.h"
#include "config/RunStatus.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "system/netlink_guards.h"
#include "system/netlink_helper.h"

namespace wpa3_tester{
using namespace std;
using namespace filesystem;

string hw_capabilities::read_sysfs(const string &iface, const string &file){
	const string path = "/sys/class/net/" + iface + "/" + file;

	ifstream ifs(path);
	if(!ifs.is_open()){ throw config_err("read_sysfs failed"); }

	string content;
	getline(ifs, content);
	if(!content.empty() && content.back() == '\n') content.pop_back();
	return content;
}

string hw_capabilities::get_driver_name(const string &iface){
	const string path = "/sys/class/net/" + iface + "/device/driver";
	try{
		if(exists(path) && is_symlink(path)){
			return read_symlink(path).filename().string();
		}
	} catch(const filesystem_error &e){
		throw config_err("Driver check error: " + string(e.what()));
	}
	throw config_err("Driver check error: not found valid symlink");;
}

optional<string> hw_capabilities::get_driver_hash(const string &driver_name){
	// try srcversion (fast, kernel-embedded)
	{
		ifstream ifs("/sys/module/" + driver_name + "/srcversion");
		if(ifs.is_open()){
			string s;
			getline(ifs, s);
			if(!s.empty()) return s;
		}
	}
	// fallback: hash the .ko file via modinfo + sha256sum
	string ko_path = run_cmd_output({"modinfo", "-F", "filename", driver_name});
	while(!ko_path.empty() && (ko_path.back() == '\n' || ko_path.back() == '\r' || ko_path.back() == ' '))
		ko_path.pop_back();
	if(ko_path.empty() || ko_path == "(builtin)") return nullopt;

	const string sha_out = run_cmd_output({"sha256sum", ko_path});
	const auto space = sha_out.find(' ');
	if(space == string::npos) return nullopt;
	return sha_out.substr(0, min(space, size_t{16}));
}

optional<string> hw_capabilities::get_module_hash(const string &driver_name){
	// module list: driver itself + comma-separated depends on from modinfo
	vector<string> modules;
	modules.push_back(driver_name);

	string deps = run_cmd_output({"modinfo", "-F", "depends", driver_name});
	while(!deps.empty() && (deps.back() == '\n' || deps.back() == '\r' || deps.back() == ' '))
		deps.pop_back();
	if(!deps.empty()){
		stringstream ss(deps);
		string tok;
		while(getline(ss, tok, ',')){
			while(!tok.empty() && (tok.back() == ' ' || tok.back() == '\r'))
				tok.pop_back();
			if(!tok.empty()) modules.push_back(tok);
		}
	}

	// Collect "module:srcversion;" for each module that has a srcversion
	string combined;
	for(const auto &mod : modules){
		ifstream ifs("/sys/module/" + mod + "/srcversion");
		if(ifs.is_open()){
			string sv;
			if(getline(ifs, sv) && !sv.empty())
				combined += mod + ":" + sv + ";";
		}
	}
	if(combined.empty()) return nullopt;

	// Write to tmp file and hash — avoids shell injection
	const auto tmp = temp_directory_path() / ("wpa3_mod_hash_" + driver_name);
	{
		ofstream f(tmp);
		if(!f.is_open()) return nullopt;
		f << combined;
	}
	const string sha_out = run_cmd_output({"sha256sum", tmp.string()});
	filesystem::remove(tmp);

	const auto space = sha_out.find(' ');
	if(space == string::npos) return nullopt;
	return sha_out.substr(0, min(space, size_t{16}));
}

string hw_capabilities::get_phy(const string &iface, const optional<string> &netns){
	netlink_helper::NetNSContext ns_guard(netns);
	const path link = "/sys/class/net/" + iface + "/phy80211";
	if(!exists(link)) return "";
	return read_symlink(link).filename().string();
}

int get_interface_arphrd_type(const path &iface_path){
	ifstream file(iface_path / "type");
	if(int type = 0; file >> type) return type;
	return 0;
}

vector<InterfaceInfo> hw_capabilities::list_interfaces(const optional<InterfaceType> filter,
														const optional<string> &netns
){
	vector<InterfaceInfo> result;
	const path net_path = "/sys/class/net";

	if(!exists(net_path)) return result;
	for(const auto &entry: directory_iterator(net_path)){
		string iface = entry.path().filename().string();

		vector<string> ignored_list{};
		if(auto g = get_global_config(); !g.empty())
			ignored_list = g.at("actors").value("ignore_interfaces", vector<string>{});

		if(set ignored_set(ignored_list.begin(), ignored_list.end()); ignored_set.contains(iface)){
			log(LogLevel::DEBUG, "Ignoring interface {} due to ignore_interfaces config", iface);
			continue;
		}

		auto type = InterfaceType::Unknown;
		if(iface == "lo"){
			type = InterfaceType::Loopback; // Loopback ('lo')
		} else if(exists(entry.path() / "wireless") || exists(entry.path() / "phy80211")){
			if(iface.rfind(AP_IFACE_PREFIX, 0) == 0){
				type = InterfaceType::WifiVirtualAP;
			} else if(iface.rfind(MONITOR_IFACE_PREFIX, 0) == 0){
				// start with prefix, not good fix
				type = InterfaceType::WifiVirtualMon; // Virtual wireless Wi-Fi (for monitor mode)
			} else if(iface.rfind(HWSIM_IFACE_PREFIX, 0) == 0){
				type = InterfaceType::WifiVirtualHwsim; // mac80211_hwsim simulation interface
			} else{
				type = InterfaceType::Wifi; // wireless Wi-Fi
			}
		} else if(exists(entry.path() / "bridge")){
			type = InterfaceType::DockerBridge; // Docker Bridge ('bridge')
		} else if(exists(entry.path() / "tun_flags")){
			type = InterfaceType::VPN; // VPN / TUN (tun_flags)
		} else if(iface.find("veth") == 0){
			type = InterfaceType::VirtualVeth; // virtual veth docker container etc)
		} else if(exists(entry.path() / "device")){
			type = InterfaceType::Ethernet; // Wire ethernet
		}
		const string radio = get_phy(iface, netns);
		if(filter.has_value()){
			if(filter.value() == type){ result.push_back({iface, radio, type}); }
		} else{
			result.push_back({iface, radio, type});
		}
	}
	return result;
}

void hw_capabilities::create_ns(const string &ns_name){
	run_cmd({"ip", "netns", "add", ns_name});
	run_cmd({"ip", "netns", "exec", ns_name, "ip", "link", "set", "lo", "up"});
}

void hw_capabilities::move_to_netns(const string &iface, const string &netns){
	log(LogLevel::INFO, "Moving interface {} to netns {}", iface, netns);

	string phy_cmd = "iw dev " + iface + " info | grep wiphy | awk '{print \"phy\"$2}'";
	string phy_name = run_cmd_output({"/bin/sh", "-c", phy_cmd});
	erase(phy_name, '\n');

	if(phy_name.empty()){
		log(LogLevel::WARNING, "Could not find physical device for interface {}", iface);
		//throw run_err("Could not find physical device for interface " + iface);
		return;
	}
	log(LogLevel::DEBUG, "Moving {} ({}) to netns {}", iface, phy_name, netns);
	run_cmd({"iw", "phy", phy_name, "set", "netns", "name", netns}, std::nullopt);
}

string hw_capabilities::get_iface(const string &ip_address, const optional<string> &netns){
	const string output = run_cmd_output({"ip", "route", "get", ip_address}, netns);
	if(output.empty()) throw run_err("Failed to get route for IP: " + ip_address);

	smatch match;
	if(!regex_search(output, match, regex(R"(dev (\S+))"))){
		throw run_err("Could not find interface for IP: " + ip_address);
	}

	return match[1].str();
}

Tins::HWAddress<6> hw_capabilities::get_mac_address(const string &iface, const optional<string> &netns){
	netlink_helper::NetNSContext ns_guard(netns);
	return read_sysfs(iface, "address");
}

string hw_capabilities::get_permanent_mac(const string &iface, const optional<string> &netns){
	const string output = run_cmd_output({"ip", "-j", "link", "show", iface}, netns);
	if(output.empty()) return {};
	try{
		auto j = nlohmann::json::parse(output);
		if(!j.empty()){
			if(j[0].contains("permaddr")) return j[0]["permaddr"].get<string>();
			if(j[0].contains("address")) return j[0]["address"].get<string>();
		}
	} catch(const exception &e){
		log(LogLevel::WARNING, "permanent mac error: {}, ignoring", e.what());
	}
	return {};
}

void hw_capabilities::set_mac_address(const string &iface, const Tins::HWAddress<6> &new_mac,
									const optional<string> &netns
){
	if(get_mac_address(iface, netns) == new_mac) return;
	set_iface_down(iface, netns);
	run_cmd({"ip", "link", "set", iface, "address", new_mac.to_string()}, netns);
}

void hw_capabilities::set_channel(const string &iface, const Channel ch, const optional<string> &netns){
	log(LogLevel::INFO, "Setting interface {} to channel {}", iface, ch.ch_num);
	if(const auto res = netlink_helper::set_channel_nl(iface, netns, ch); !res)
		throw timeout_err("Timeout waiting for '" + iface + "' to switch to channel " + to_string(ch.ch_num) + ": " + res.error().message());
}

string get_iface_type(const string &iface, const optional<string> &netns){
	const string output = hw_capabilities::run_cmd_output({"iw", iface, "info"}, netns);
	if(output.empty()) throw run_err("Failed to get interface info for: " + iface);

	smatch match;
	if(!regex_search(output, match, regex(R"(type (\w+))")))
		throw run_err("Could not determine interface type for: " + iface);

	return match[1].str();
}

bool hw_capabilities::set_monitor_active(const string &iface, const optional<string> &netns, const Channel ch){
	set_iface_down(iface, netns);

	if(run_cmd({"iw", "dev", iface, "set", "monitor", "active"}) != 0){
		log(LogLevel::WARNING, format("Interface {} failed to enter monitor mode", iface));
		return false;
	}
	set_iface_up(iface, netns);
	if(ch.ch_num > 0){
		if(run_cmd({"iw", "dev", iface, "set", "channel", to_string(ch.ch_num)}) != 0){
			log(LogLevel::WARNING, format("Failed to set channel {} on {}", ch.ch_num, iface));
			return false;
		}
	}
	return true;
}

void hw_capabilities::set_iface_down(const string &iface, const optional<string> &netns){
	run_cmd({"ip", "link", "set", iface, "down"}, netns);
	if(const auto res = netlink_helper::wait_for_link_flags(iface, netns, false); !res) throw timeout_err(
		"Timeout waiting for '" + iface + "' to go DOWN:" + res.error().message());
}

void hw_capabilities::set_iface_up(const string &iface, const optional<string> &netns){
	run_cmd({"ip", "link", "set", iface, "up"}, netns);
	if(const auto res = netlink_helper::wait_for_link_flags(iface, netns, true); !res) throw timeout_err(
		"Timeout waiting for '" + iface + "' to go UP:" + res.error().message());
}
void hw_capabilities::set_wifi_type(const string_view iface, const nl80211_iftype type, const optional<string> &netns, const vector<string> &monitor_flags){
	if(netlink_helper::query_wifi_iftype(iface, netns) == type) return;

	const auto *type_str = [&]() ->const char *{
		switch(type){
		case NL80211_IFTYPE_MONITOR: return "monitor";
		case NL80211_IFTYPE_STATION: return "managed";
		case NL80211_IFTYPE_AP: return "__ap";
		default: throw run_err(format("Unsupported nl80211 iftype: {}", static_cast<int>(type)));
		}
	}();

	if(const int ret = run_cmd({"iw", "dev", iface.data(), "set", "type", type_str}, netns); ret != 0) throw
			run_err(format("iw set type {} on '{}' failed: {}", type_str, iface, ret));

	if(const auto res = netlink_helper::wait_for_wifi_iftype(iface, netns, type); !res)
		throw run_err(format("Timeout waiting for '{}' to reach type '{}': {}", iface, type_str,
									res.error().message()));

	if(type == NL80211_IFTYPE_MONITOR && !monitor_flags.empty()){
		vector<string> cmd = {"iw", "dev", iface.data(), "set", "monitor"};
		cmd.insert(cmd.end(), monitor_flags.begin(), monitor_flags.end());
		run_cmd(cmd, netns);
	}
}
}