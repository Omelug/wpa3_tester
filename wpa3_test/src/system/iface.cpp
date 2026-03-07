#include <sys/wait.h>
#include <vector>
#include <fstream>

#include "system/iface.h"

#include <random>

#include "logger/log.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester{
    using namespace std;
    //TODO create test for this
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
        run({"sudo","ip", "link", "set", name, "down"});
        run({"sudo","iw", "dev", name, "set", "type", "monitor"});
        run({"sudo","ip", "link", "set", name, "up"});
    }

    void iface::cleanup() const {
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

    void iface::create_sniff_iface(const std::string& sniff_iface){
        run({"iw", "dev", name, "interface","add",sniff_iface,"type","monitor","flags","fcsfail", "otherbss"});
    }

    iface::iface(std::string name, std::optional<std::string> netns)
        : name(std::move(name)), netns(std::move(netns)) {}

    int iface::run(const std::vector<std::string> &argv) const{
        return hw_capabilities::run_cmd(argv, netns);
    }

    bool iface::is_physical_interface(const std::string& iface_name) {
        const filesystem::path p = filesystem::path("/sys/class/net") / iface_name / "device";
        return filesystem::exists(p);
    }

    /*string iface::get_mac_address(const std::string& iface_name, const std::optional<std::string>& netns) {
        // If no netns specified, read directly from sysfs
        if (!netns.has_value()) {
            const filesystem::path mac_path = filesystem::path("/sys/class/net") / iface_name / "address";

            if (!filesystem::exists(mac_path)) {
                throw runtime_error("Interface " + iface_name + " not found or has no MAC address");
            }

            ifstream mac_file(mac_path);
            if (!mac_file.is_open()) {
                throw runtime_error("Failed to read MAC address for interface " + iface_name);
            }

            string mac_addr;
            getline(mac_file, mac_addr);

            mac_addr.erase(0, mac_addr.find_first_not_of(" \t\r\n"));
            mac_addr.erase(mac_addr.find_last_not_of(" \t\r\n") + 1);

            return mac_addr;
        }

        // If netns specified, use ip command to get MAC address
        // Build command: ip netns exec <netns> cat /sys/class/net/<iface>/address
        vector<string> cmd = {
            "ip", "netns", "exec", netns.value(),
            "cat", "/sys/class/net/" + iface_name + "/address"
        };

        // Execute command and capture output
        string full_cmd;
        for (size_t i = 0; i < cmd.size(); ++i) {
            if (i > 0) full_cmd += " ";
            full_cmd += cmd[i];
        }
        full_cmd += " 2>&1";

        FILE* pipe = popen(full_cmd.c_str(), "r");
        if (!pipe) {
            throw runtime_error("Failed to execute command to get MAC address for " + iface_name + " in netns " + netns.value());
        }

        char buffer[128];
        string mac_addr;
        if (fgets(buffer, sizeof(buffer), pipe)) {
            mac_addr = string(buffer);
        }

        int status = pclose(pipe);
        if (status != 0 || mac_addr.empty()) {
            throw runtime_error("Interface " + iface_name + " not found in netns " + netns.value() + " or has no MAC address");
        }

        mac_addr.erase(0, mac_addr.find_first_not_of(" \t\r\n"));
        mac_addr.erase(mac_addr.find_last_not_of(" \t\r\n") + 1);

        return mac_addr;
    }*/

    string iface::rand_mac() {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);

        char mac[18];
        snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 dis(gen), dis(gen), dis(gen), dis(gen), dis(gen), dis(gen));
        return string(mac);
    }
}
