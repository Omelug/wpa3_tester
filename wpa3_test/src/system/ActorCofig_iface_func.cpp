#include <sys/wait.h>
#include <vector>
#include <fstream>



#include <random>

#include "logger/log.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester{
    using namespace std;

    //TODO create test for this
    void Actor_config::set_channel(const int channel) const {
        if (netns.has_value()) {
            log(LogLevel::INFO, "Setting interface %s to channel %d in netns %s", name.c_str(), channel, netns->c_str());
        } else {
            log(LogLevel::INFO, "Setting interface %s to channel %d", name.c_str(), channel);
        }
        run({"iw", "dev", name, "set", "channel", std::to_string(channel)});
    }

    void Actor_config::set_managed_mode() const {
        if (netns.has_value()) {
            log(LogLevel::INFO, "Preparing interface %s for managed mode in netns %s", name.c_str(), netns->c_str());
        } else {
            log(LogLevel::INFO, "Preparing interface %s for managed mode", name.c_str());
        }
        run({"ip", "link", "set", name, "down"});
        run({"iw", "dev", name, "set", "type", "managed"});
        run({"ip", "link", "set", name, "up"});
    }

    void Actor_config::set_monitor_mode() const {
        if (netns.has_value()) {
            log(LogLevel::INFO, "Setting interface %s to monitor mode in netns %s", name.c_str(), netns->c_str());
        } else {
            log(LogLevel::INFO, "Setting interface %s to monitor mode", name.c_str());
        }
        run({"sudo","ip", "link", "set", name, "down"});
        run({"sudo", "iw", "dev", name, "set", "type", "monitor"});
        run({"sudo", "iw", "dev", name, "set", "monitor", "fcsfail", "otherbss"});
        run({"sudo","ip", "link", "set", name, "up"});
    }

    void Actor_config::cleanup() const {
        string name = str_con["iface"];
        if (name.empty()) {
            log(LogLevel::ERROR, "cleanup() called with empty interface name");
            return;
        }

        if (netns.has_value()) {
            log(LogLevel::INFO, "Cleaning up interface %s in netns %s", name.c_str(), netns->c_str());

            const string phy_find_cmd = "iw dev " + name + " info 2>/dev/null | grep wiphy | awk '{print \"phy\"$2}'";
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

    void Actor_config::create_sniff_iface(const std::string& sniff_iface){
        run({"iw", "dev", name, "interface","add",sniff_iface,"type","monitor","flags","fcsfail", "otherbss"});
        run({"ip", "link", "set", sniff_iface, "up"});
    }

    int Actor_config::run(const std::vector<std::string> &argv) const{
        return hw_capabilities::run_cmd(argv, netns);
    }
}
