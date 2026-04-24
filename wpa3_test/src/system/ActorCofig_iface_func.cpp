#include <sys/wait.h>
#include <vector>
#include <random>

#include "ex_program/external_actors/ExternalConn.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester{
using namespace std;

void Actor_config::set_channel(const int channel, const string &ht_mode) const{
    const string &iface = str_con.at("iface").value();

    if(conn != nullptr){
        conn->set_channel(iface, channel, ht_mode);
        return;
    }

    const string chan_str = to_string(channel);
    log(LogLevel::INFO, "Setting interface " + iface + " to channel " + chan_str + " " + ht_mode);

    vector<string> cmd = {"iw", "dev", iface, "set", "channel", chan_str};
    if(!ht_mode.empty()) cmd.push_back(ht_mode);
    run(cmd);
}

bool is_interface_up(const string &iface){
    ifstream status_file("/sys/class/net/" + iface + "/operstate");
    string status;
    if(status_file >> status){ return (status == "up"); }
    return false;
}

void Actor_config::cleanup() const{
    string iface = str_con.at("iface").value();
    optional<string> netns = str_con.at("netns");
    if(iface.empty()){
        log(LogLevel::ERROR, "cleanup() called with empty interface name");
        return;
    }

    if(netns.has_value()){
        log(LogLevel::INFO, "Cleaning up interface " + iface + " in netns " + *netns);

        const string phy_find_cmd = "iw dev " + iface + " info 2>/dev/null | grep wiphy | awk '{print \"phy\"$2}'";
        char buffer[128];
        string phy_name;
        FILE *pipe = popen(phy_find_cmd.c_str(), "r");
        if(pipe && fgets(buffer, sizeof(buffer), pipe)){
            phy_name = string(buffer);
            phy_name.erase(phy_name.find_last_not_of(" \n\r\t") + 1); // trim
        }
        if(pipe) pclose(pipe);

        if(!phy_name.empty()){
            log(LogLevel::DEBUG, "Moving " + iface + " (" + phy_name + ") to netns " + *netns);
            hw_capabilities::run_cmd({"iw", "phy", phy_name, "set", "netns", "name", netns.value()}, nullopt);
        }
    } else{
        log(LogLevel::INFO, "Cleaning up interface " + iface);
    }

    // FIXME taohle by nemělo být potřeba po testu
    run({"pkill", "-f", "tshark.*" + iface});
    run({"pkill", "-f", "tcpdump.*" + iface});

    run({"rm", "-f", "/var/run/wpa_supplicant/" + iface});
    if(str_con.at("sniff_iface").has_value()){
        run({"iw", "dev", str_con.at("sniff_iface").value(), "del"});

        run({"pkill", "-f", "wpa_supplicant.*-i" + iface});
        run({"pkill", "-f", "hostapd.*" + iface});

        set_iface_down();
        run({"rfkill", "unblock", "wifi"});
    }
    run({"ip", "addr", "flush", "dev", iface});
    set_iface_up();
}

void Actor_config::create_sniff_iface() const{
    const string &iface = str_con.at("iface").value();
    const string &sniff_iface = str_con.at("sniff_iface").value();
    if(conn != nullptr){
        throw not_implemented_err("External cant have sniff_iface");
        //conn->create_sniff_iface(iface, sniff_iface); return;
    }

    if(run({"ip", "link", "show", sniff_iface}) == 0){
        log(LogLevel::INFO, "Sniff interface %s already exists. Setting UP.", sniff_iface.c_str());
        set_iface_up();
        return;
    }

    log(LogLevel::DEBUG, "Interface %s not found, creating new one.", sniff_iface.c_str());
    const auto fd_count = distance(filesystem::directory_iterator("/proc/self/fd"),
                                   filesystem::directory_iterator{});
    log(LogLevel::DEBUG, "Current open FDs: %ld %s %s", fd_count, iface.c_str(), sniff_iface.c_str());

    string monitor_flags;
    vector<string> cmd =
            {"iw", "dev", iface, "interface", "add", sniff_iface, "type", "monitor", "flags", "fcsfail", "otherbss"};
    if(bool_conditions.at("active_monitor")) cmd.emplace_back("active");
    if(bool_conditions.at("control_monitor")) cmd.emplace_back("control");
    run(cmd);
    set_iface_up();
}

//------------------ get status info functions

void Actor_config::set_ap_mode() const{
    const string &iface = str_con.at("iface").value();
    log(LogLevel::INFO, "Preparing interface " + iface + " for AP mode");

    set_iface_down();
    run({"iw", "dev", iface, "set", "type", "__ap"});
    //run({"ip", "addr", "add", "192.168.1.1/24", "dev", iface});
}

void Actor_config::up_sniff_iface() const{
    if(!str_con.at("sniff_iface").has_value()) return;
    const string &sniff_iface = str_con.at("sniff_iface").value();

    if(is_interface_up(sniff_iface)){
        log(LogLevel::DEBUG, sniff_iface + " is already UP, skipping.");
        return;
    }
    log(LogLevel::INFO, "Bringing " + sniff_iface + " UP...");
    run({"ip", "link", "set", sniff_iface, "up"});
}

void Actor_config::set_managed_mode() const{
    const string &iface = str_con.at("iface").value();
    if(conn != nullptr){
        conn->set_managed_mode(iface);
        return;
    }
    const optional<string> netns = str_con.at("netns");

    log(LogLevel::INFO, "Preparing interface" + iface + " for managed mode");
    set_iface_down();
    run({"iw", "dev", iface, "set", "type", "managed"});
}

void Actor_config::set_mac_address(const string &mac) const{
    const string &iface = str_con.at("iface").value();
    if(conn != nullptr){ throw not_implemented_err("not valid for external "); }
    hw_capabilities::set_mac_address(iface, mac, str_con.at("netns"));

    if(str_con.contains("sniff_iface") && str_con.at("sniff_iface").has_value()){
        hw_capabilities::set_mac_address(str_con.at("sniff_iface").value(), mac, str_con.at("netns"));
    }
}

//TODO nejdřív napsat pořádné testy, apk optimalizavat
void Actor_config::set_monitor_mode(const string &monitor_flags) const{
    const string &iface = str_con.at("iface").value();
    if(conn != nullptr){
        conn->set_monitor_mode(iface);
        return;
    }

    log(LogLevel::INFO, "Setting interface " + iface + " to monitor mode+" + monitor_flags);
    set_iface_down();

    run({"iw", "dev", iface, "set", "type", "monitor"});
    vector<string> flags = {"iw", "dev", iface, "set", "monitor", "fcsfail", "otherbss"};
    if(!monitor_flags.empty()){
        flags.push_back(monitor_flags);
    }
    run(flags);
}

// -------- hw_capabilities wrappers

int Actor_config::run(const vector<string> &argv) const{
    return hw_capabilities::run_cmd(argv, str_con.at("netns"));
}

string Actor_config::get_driver_name() const{
    return hw_capabilities::get_driver_name(str_con.at("iface").value());
}

void Actor_config::set_iface_down() const{
    hw_capabilities::set_iface_down(str_con.at("iface").value(), str_con.at("netns"));
}

void Actor_config::set_iface_up() const{
    hw_capabilities::set_iface_up(str_con.at("iface").value(), str_con.at("netns"));
}

void Actor_config::set_wifi_type(const nl80211_iftype type) const{
    hw_capabilities::set_wifi_type(str_con.at("iface").value(), type, str_con.at("netns"));
}


}
