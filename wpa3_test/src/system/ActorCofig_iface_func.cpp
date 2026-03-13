#include <sys/wait.h>
#include <vector>
#include <random>

#include "ex_program/external_actors/ExternalConn.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester{
    using namespace std;

    //TODO nějak strašně ukecané s těma logama

    //TODO create test for this
    void Actor_config::set_channel(const int channel) const{
        const string& iface = str_con.at("iface").value();
        if(conn.get() != nullptr){conn->set_channel(iface, channel); return;}
        const optional<string> netns = str_con.at("netns");
        if (netns.has_value()) {
            log(LogLevel::INFO, "Setting interface %s to channel %d in netns %s",
                iface.c_str(), channel, netns->c_str());
        } else {
            log(LogLevel::INFO, "Setting interface %s to channel %d", iface.c_str(), channel);
        }
        run({"iw", "dev", iface, "set", "channel", std::to_string(channel)});
    }

    void Actor_config::set_managed_mode() const{
        const string& iface = str_con.at("iface").value();
        if(conn.get() != nullptr){conn->set_managed_mode(iface); return;}
        const optional<string> netns = str_con.at("netns");

        if (netns.has_value()) {
            log(LogLevel::INFO, "Preparing interface "+iface+" for managed mode in netns " + netns.value());
        } else {log(LogLevel::INFO, "Preparing interface"+iface+" for managed mode");}

        run({"ip", "link", "set", iface, "down"});
        run({"iw", "dev", iface, "set", "type", "managed"});
        run({"ip", "link", "set", iface, "up"});
    }

    void Actor_config::set_monitor_mode() const{
        const string& iface = str_con.at("iface").value();
        if(conn.get() != nullptr){conn->set_monitor_mode(iface); return;}
        const optional<string> netns = str_con.at("netns");
        if (netns.has_value()) {
            log(LogLevel::INFO, "Setting interface "+iface+" to monitor mode in netns "+ netns.value());
        } else {log(LogLevel::INFO, "Setting interface "+iface+" to monitor mode");}

        run({"sudo","ip", "link", "set", iface, "down"});
        run({"sudo", "iw", "dev", iface, "set", "type", "monitor"});
        run({"sudo", "iw", "dev", iface, "set", "monitor", "fcsfail", "otherbss"});
        run({"sudo","ip", "link", "set", iface, "up"});
    }

    void Actor_config::cleanup() const {
        string iface = str_con.at("iface").value();
        optional<string> netns = str_con.at("netns");
        if (iface.empty()) {
            log(LogLevel::ERROR, "cleanup() called with empty interface name");
            return;
        }

        if (netns.has_value()) {
            log(LogLevel::INFO, "Cleaning up interface %s in netns %s", iface.c_str(), netns->c_str());

            const string phy_find_cmd = "iw dev " + iface + " info 2>/dev/null | grep wiphy | awk '{print \"phy\"$2}'";
            char buffer[128];
            string phy_name;
            FILE* pipe = popen(phy_find_cmd.c_str(), "r");
            if (pipe && fgets(buffer, sizeof(buffer), pipe)) {
                phy_name = string(buffer);
                phy_name.erase(phy_name.find_last_not_of(" \n\r\t") + 1); // trim
            }
            if (pipe) pclose(pipe);

            if (!phy_name.empty()) {
                log(LogLevel::DEBUG, "Moving %s (%s) to netns %s", iface.c_str(), phy_name.c_str(), netns->c_str());
                hw_capabilities::run_cmd({"iw", "phy", phy_name, "set", "netns", "name", netns.value()}, std::nullopt);
            }

        } else {
            log(LogLevel::INFO, "Cleaning up interface %s", iface.c_str());
        }

        run({"pkill", "-f", "wpa_supplicant.*-i" + iface});
        run({"pkill", "-f", "hostapd.*" + iface});
        run({"ip", "link", "set", iface, "down"});
        run({"rfkill", "unblock", "wifi"});
        run({"ip", "addr", "flush", "dev", iface});
        run({"ip", "link", "set", iface, "up"});
    }

    void Actor_config::create_sniff_iface(const std::string& sniff_iface) const{
        const string& iface = str_con.at("iface").value();
        if(conn.get() != nullptr){conn->create_sniff_iface(iface, sniff_iface); return;}

        //TODo quite fallback
        if (run({"iw", "dev", iface, "interface", "add", sniff_iface, "type", "monitor",
            "flags", "fcsfail", "otherbss"}) != 0){
            run({"iw", "dev", iface, "interface", "add", sniff_iface, "type", "monitor"});
        }
        run({"ip", "link", "set", sniff_iface, "up"});
    }

    int Actor_config::run(const std::vector<std::string> &argv) const{
        return hw_capabilities::run_cmd(argv, str_con.at("netns"));
    }
}
