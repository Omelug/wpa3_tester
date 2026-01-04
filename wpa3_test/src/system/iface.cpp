#include <sys/wait.h>
#include <vector>

#include "system/iface.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"

using namespace std;

void iface::set_channel(const int channel) const {
    if (netns.has_value()) {
        log(LogLevel::INFO, "Setting interface %s to channel %d in netns %s", name.c_str(), channel, netns->c_str());
    } else {
        log(LogLevel::INFO, "Setting interface %s to channel %d", name.c_str(), channel);
    }
    run({"iw", "dev", name, "set", "channel", std::to_string(channel)});
}

void iface::set_managed_mode() const {
    if (netns.has_value()) {
        log(LogLevel::INFO, "Preparing interface %s for managed mode in netns %s", name.c_str(), netns->c_str());
    } else {
        log(LogLevel::INFO, "Preparing interface %s for managed mode", name.c_str());
    }
    run({"ip", "link", "set", name, "down"});
    run({"iw", "dev", name, "set", "type", "managed"});
    run({"ip", "link", "set", name, "up"});
}

void iface::set_monitor_mode() const {
    if (netns.has_value()) {
        log(LogLevel::INFO, "Setting interface %s to monitor mode in netns %s", name.c_str(), netns->c_str());
    } else {
        log(LogLevel::INFO, "Setting interface %s to monitor mode", name.c_str());
    }
    run({"ip", "link", "set", name, "down"});
    run({"iw", "dev", name, "set", "type", "monitor"});
    run({"ip", "link", "set", name, "up"});
}

void iface::cleanup() const {
    if (name.empty()) {
        log(LogLevel::ERROR, "cleanup() called with empty interface name");
        return;
    }
    if (netns.has_value()) {
        log(LogLevel::INFO, "Cleaning up interface %s in netns %s", name.c_str(), netns->c_str());

        string phy_find_cmd = "iw dev " + name + " info 2>/dev/null | grep wiphy | awk '{print \"phy\"$2}'";
        char buffer[128];
        string phy_name;
        FILE* pipe = popen(phy_find_cmd.c_str(), "r");
        if (pipe && fgets(buffer, sizeof(buffer), pipe)) {
            phy_name = string(buffer);
            phy_name.erase(phy_name.find_last_not_of(" \n\r\t") + 1); // trim
        }
        if (pipe) pclose(pipe);

        if (!phy_name.empty()) {
            log(LogLevel::DEBUG, "Moving %s (%s) to netns %s", name.c_str(), phy_name.c_str(), netns->c_str());
            hw_capabilities::run_cmd({"iw", "phy", phy_name, "set", "netns", "name", netns.value()}, std::nullopt);
        }
    } else {
        log(LogLevel::INFO, "Cleaning up interface %s", name.c_str());
    }

    run({"pkill", "-f", "wpa_supplicant.*-i" + name});
    run({"pkill", "-f", "hostapd.*" + name});
    run({"ip", "link", "set", name, "down"});
    run({"rfkill", "unblock", "wifi"});
    run({"ip", "addr", "flush", "dev", name});
    run({"ip", "link", "set", name, "up"});
}


iface::iface(std::string name, std::optional<std::string> netns)
    : name(std::move(name)), netns(std::move(netns)) {}

int iface::run(const std::vector<std::string> &argv) const{
    return hw_capabilities::run_cmd(argv, netns);
}
