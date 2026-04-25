#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <set>
#include <string>
#include <unistd.h>
#include <vector>
#include <sys/types.h>
#include <sys/wait.h>
#include <random>
#include <reproc++/drain.hpp>
#include "system/hw_capabilities.h"
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

string hw_capabilities::get_phy(const string &iface, const optional<string> &netns){
    netlink_helper::NetNSContext ns_guard(netns);
    const path link = "/sys/class/net/" + iface + "/phy80211";
    if(!exists(link)) return "";
    return read_symlink(link).filename().string();
}

int get_interface_arphrd_type(const path &iface_path){
    ifstream file(iface_path / "type");
    int type = 0;
    if(file >> type) return type;
    return 0;
}

vector<InterfaceInfo> hw_capabilities::list_interfaces(const optional<InterfaceType> filter,
                                                       const optional<string> &netns){
    vector<InterfaceInfo> result;
    const path net_path = "/sys/class/net";

    if(!exists(net_path)) return result;
    for(const auto &entry: directory_iterator(net_path)){
        string iface = entry.path().filename().string();

        auto ignored_list = get_global_config().at("actors").value("ignore_interfaces", vector<string>{});

        if(set ignored_set(ignored_list.begin(), ignored_list.end()); ignored_set.contains(iface)){
            log(LogLevel::DEBUG, "Ignoring interface " + iface + " due to ignore_interfaces config");
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

void hw_capabilities::move_to_netns(const string &iface, const string &netns) {
    log(LogLevel::INFO, "Moving interface " + iface + " to netns " + netns);

    string phy_cmd = "iw dev " + iface + " info | grep wiphy | awk '{print \"phy\"$2}'";
    string phy_name = run_cmd_output({"/bin/sh", "-c", phy_cmd});
    std::erase(phy_name, '\n');

    if (phy_name.empty()){
        log(LogLevel::WARNING, "Could not find physical device for interface " + iface);
        //throw std::runtime_error("Could not find physical device for interface " + iface);
        return;
    }
    log(LogLevel::DEBUG, "Moving " + iface + " (" + phy_name + ") to netns " + netns);
    run_cmd({"iw", "phy", phy_name, "set", "netns", "name", netns}, std::nullopt);
}

string hw_capabilities::get_iface(const string &ip_address, const optional<string> &netns){
    const string output = run_cmd_output({"ip", "route", "get", ip_address}, netns);
    if(output.empty()) throw runtime_error("Failed to get route for IP: " + ip_address);

    smatch match;
    if(!regex_search(output, match, regex(R"(dev (\S+))"))){
        throw runtime_error("Could not find interface for IP: " + ip_address);
    }

    return match[1].str();
}

string hw_capabilities::get_macaddress(const string &iface, const optional<string> &netns){
    netlink_helper::NetNSContext ns_guard(netns);
    ifstream f("/sys/class/net/" + iface + "/address");
    string mac;
    getline(f, mac);
    return mac;
}

void hw_capabilities::set_mac_address(const string &iface, const string &new_mac_str, const optional<string> &netns){
    if(get_macaddress(iface, netns) == new_mac_str) return;
    set_iface_down(iface, netns);
    run_cmd({"macchanger", "-m", new_mac_str, iface}, netns);
}

void hw_capabilities::supports_active_monitor(const string &iface, Actor_config &cfg, const optional<string> &netns){
    const string result = run_cmd_output({"iw", "dev", iface, "info"}, netns);

    // find "wiphy X"
    int phy_idx = -1;
    istringstream ss(result);
    string line;
    while(getline(ss, line)){
        if(line.find("wiphy") != string::npos){
            sscanf(line.c_str(), " wiphy %d", &phy_idx);
            break;
        }
    }
    if(phy_idx < 0){
        cfg.bool_conditions["active_monitor"] = false;
        return;
    }

    const string phy_info = run_cmd_output({"iw", "phy", "phy" + to_string(phy_idx), "info"}, netns);
    istringstream ss2(phy_info);
    while(getline(ss2, line)){
        if(line.find("active monitor") != string::npos){
            cfg.bool_conditions["active_monitor"] = true;
            return;
        }
    }
    cfg.bool_conditions["active_monitor"] = false;
}

void hw_capabilities::set_channel(const string &iface, const int channel, const optional<string> &netns){
    log(LogLevel::INFO, "Setting interface "+iface+" to channel "+to_string(channel));
    run_cmd({"iw", "dev", iface, "set", "channel", to_string(channel)}, netns);
}

string get_iface_type(const string &iface, const optional<string> &netns){
    const string output = hw_capabilities::run_cmd_output({"iw", iface, "info"}, netns);
    if(output.empty()) throw runtime_error("Failed to get interface info for: " + iface);

    smatch match;
    if(!regex_search(output, match, regex(R"(type (\w+))"))) throw runtime_error(
        "Could not determine interface type for: " + iface);

    return match[1].str();
}

bool hw_capabilities::set_monitor_active(const string &iface, const optional<string> &netns, int channel){
    set_iface_down(iface, netns);

    if(run_cmd({"iw", "dev", iface, "set", "monitor", "active"}) != 0){
        log(LogLevel::WARNING, format("Interface {} failed to enter monitor mode", iface));
        return false;
    }
    set_iface_up(iface, netns);
    if(channel > 0){
        if(run_cmd({"iw", "dev", iface, "set", "channel", to_string(channel)}) != 0){
            log(LogLevel::WARNING, format("Failed to set channel {} on {}", channel, iface));
            return false;
        }
    }
    return true;
}

void hw_capabilities::set_iface_down(const string &iface, const optional<string> &netns){
    run_cmd({"ip", "link", "set", iface, "down"}, netns);
    if(const auto res = netlink_helper::wait_for_link_flags(iface, netns, false); !res)
        throw timeout_err("Timeout waiting for '"+iface+"' to go DOWN:"+ res.error().message());
}

void hw_capabilities::set_iface_up(const string &iface, const optional<string> &netns){
    run_cmd({"ip", "link", "set", iface, "up"}, netns);
    if(const auto res = netlink_helper::wait_for_link_flags(iface, netns, true); !res)
        throw timeout_err("Timeout waiting for '"+iface+"' to go UP:"+ res.error().message());
}

//TODO add monitor flags
void hw_capabilities::set_wifi_type(const string_view iface, const nl80211_iftype type, const optional<string> &netns){
    if(netlink_helper::query_wifi_iftype(iface, netns) == type) return;

    const auto *type_str = [&]() ->const char *{
        switch(type){
            case NL80211_IFTYPE_MONITOR: return "monitor";
            case NL80211_IFTYPE_STATION: return "managed";
            case NL80211_IFTYPE_AP: return "__ap";
            default: throw runtime_error(format("Unsupported nl80211 iftype: {}", static_cast<int>(type)));
        }
    }();

    if(const int ret = run_cmd({"iw", "dev", iface.data(), "set", "type", type_str}, netns); ret != 0)
        throw runtime_error(format("iw set type {} on '{}' failed: {}", type_str, iface, ret));

    if(const auto res = netlink_helper::wait_for_wifi_iftype(iface, netns, type); !res)
        throw runtime_error(format("Timeout waiting for '{}' to reach type '{}': {}",
                                   iface, type_str, res.error().message()));
}
}