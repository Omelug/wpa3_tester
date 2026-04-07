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
#include <reproc++/reproc.hpp>

#include "system/hw_capabilities.h"
#include "config/global_config.h"
#include "config/RunStatus.h"
#include "logger/error_log.h"
#include "logger/log.h"

namespace wpa3_tester{
    using namespace std;
    using namespace filesystem;

    string hw_capabilities::read_sysfs(const string &iface, const string &file){
        const string path = "/sys/class/net/"+iface+"/"+file;

        ifstream ifs(path);
        if(!ifs.is_open()){ throw config_err("read_sysfs failed");}

        string content;
        getline(ifs, content);
        if(!content.empty() && content.back() == '\n') content.pop_back();
        return content;
    }

    string hw_capabilities::get_driver_name(const string &iface){
        const string path = "/sys/class/net/"+iface+"/device/driver";
        try{
            if(exists(path) && is_symlink(path)){
                return read_symlink(path).filename().string();
            }
        } catch(const filesystem_error &e){
            throw config_err("Driver check error: "+string(e.what()));
        }
        throw config_err("Driver check error: not found valid symlink"); ;
    }

    string hw_capabilities::get_phy(const string &iface) {
        const path link = "/sys/class/net/"+iface+"/phy80211";
        if (!exists(link)) return "";
        return read_symlink(link).filename().string();
    }

    int get_interface_arphrd_type(const path& iface_path) {
        ifstream file(iface_path / "type");
        int type = 0;
        if (file >> type) return type;
        return 0;
    }

    vector<InterfaceInfo> hw_capabilities::list_interfaces(const optional<InterfaceType> filter){
        vector<InterfaceInfo> result;
        const path net_path = "/sys/class/net";

        if(!exists(net_path)) return result;
        for(const auto &entry: directory_iterator(net_path)){
            string iface = entry.path().filename().string();

            auto ignored_list = get_global_config().at("actors").value("ignore_interfaces", vector<string>{});

            if(set ignored_set(ignored_list.begin(), ignored_list.end()); ignored_set.contains(iface)){
                log(LogLevel::DEBUG, "Ignoring interface "+iface+" due to ignore_interfaces config");
                continue;
            }

            auto type = InterfaceType::Unknown;
            if(iface == "lo"){
                type = InterfaceType::Loopback;  // Loopback ('lo')
            }else if(exists(entry.path() / "wireless") || exists(entry.path() / "phy80211")){
                if(iface.rfind(MONITOR_IFACE_PREFIX, 0) == 0) { // start with prefix, not good fix
                    type = InterfaceType::WifiVirtualMon;  // Virtual wireless Wi-Fi (for monitor mode)
                }else{
                    type = InterfaceType::Wifi;   // wireless Wi-Fi
                }

            }else if(exists(entry.path() / "bridge")){
                type = InterfaceType::DockerBridge;  // Docker Bridge ('bridge')
            }else if(exists(entry.path() / "tun_flags")){
                type = InterfaceType::VPN; // VPN / TUN (tun_flags)
            } else if(iface.find("veth") == 0){
                type = InterfaceType::VirtualVeth; // virtual veth docker container etc)
            } else if(exists(entry.path() / "device")){
                type = InterfaceType::Ethernet; // Wire ethernet
            }
            const string radio = get_phy(iface);
            if(filter.has_value()){
                if(filter.value() == type){result.push_back({iface, radio,type});}
            }else{
                result.push_back({iface, radio,type});
            }
        }
        return result;
    }

    void hw_capabilities::create_ns(const string &ns_name){
        run_cmd({"ip", "netns", "add", ns_name});
        run_cmd({"ip", "netns", "exec", ns_name, "ip", "link", "set", "lo", "up"});
    }

    string hw_capabilities::get_iface(const string& ip_address) {
        const string output = run_cmd_output({"ip", "route", "get", ip_address});
        if (output.empty()) throw runtime_error("Failed to get route for IP: "+ip_address);

        smatch match;
        if (!regex_search(output, match, regex(R"(dev (\S+))"))){throw runtime_error("Could not find interface for IP: "+ip_address);}

        return match[1].str();
    }

    string hw_capabilities::get_macaddress(const string& iface) {
        ifstream f("/sys/class/net/" + iface + "/address");
        string mac;
        getline(f, mac);
        return mac;
    }

    void hw_capabilities::set_macaddress(const string& iface, const string& new_mac_str) {
        if (get_macaddress(iface) == new_mac_str) return;
        run_cmd({"ifconfig",iface,"down"});
        run_cmd({"macchanger", "-m", new_mac_str, iface});
    }

    void hw_capabilities::supports_active_monitor(const string &iface, Actor_config &cfg) {

        const string result = run_cmd_output({"iw", "dev", iface, "info"});

        // find "wiphy X"
        int phy_idx = -1;
        istringstream ss(result);
        string line;
        while (getline(ss, line)) {
            if (line.find("wiphy") != string::npos) {
                sscanf(line.c_str(), " wiphy %d", &phy_idx);
                break;
            }
        }
        if (phy_idx < 0) {
            cfg.bool_conditions["active_monitor"] = false;
            return;
        }

        const string phy_info = run_cmd_output({"iw", "phy", "phy" + to_string(phy_idx), "info"});
        istringstream ss2(phy_info);
        while (getline(ss2, line)) {
            if (line.find("active monitor") != string::npos) {
                cfg.bool_conditions["active_monitor"] = true;
                return;
            }
        }
        cfg.bool_conditions["active_monitor"] = false;
    }

    void hw_capabilities::set_channel(const string &iface, const int channel){
        const string chan_str = to_string(channel);
        log(LogLevel::INFO, "Setting interface " + iface + " to channel " + chan_str);
        const vector<string> cmd = {"iw", "dev", iface, "set", "channel", chan_str};
        run_cmd(cmd);
    }

    string get_iface_type(const string& iface){
        const string output = hw_capabilities::run_cmd_output({"iw", iface, "info"});
        if (output.empty())
            throw runtime_error("Failed to get interface info for: " + iface);

        smatch match;
        if (!regex_search(output, match, regex(R"(type (\w+))")))
            throw runtime_error("Could not determine interface type for: " + iface);

        return match[1].str();
    }
    
    bool hw_capabilities::set_monitor_active(const string& iface){
        run_cmd({"ifconfig", iface, "down"});
        if (run_cmd({"iw", iface, "set", "monitor", "active"}) != 0) {
            log(LogLevel::WARNING, format("Interface {} doesn't support active monitor mode", iface));
            return false;
        }
        return true;
    }

    void hw_capabilities::set_monitor_mode(const string& iface, const int mtu){
        if (get_iface_type(iface) != "monitor") {
            run_cmd({"ifconfig", iface, "down"});
            run_cmd({"iw", iface, "set", "monitor", "none"});
            this_thread::sleep_for(chrono::milliseconds(500));
            run_cmd({"iw", iface, "set", "monitor", "none"});
        }
        run_cmd({"ifconfig", iface, "up"});
        run_cmd({"ifconfig", iface, "mtu", to_string(mtu)});
    }
}
