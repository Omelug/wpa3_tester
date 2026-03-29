#include <sys/wait.h>
#include <vector>
#include <random>

#include "ex_program/external_actors/ExternalConn.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester{
    using namespace std;

    void Actor_config::set_channel(const int channel, const string& ht_mode) const {
        const string& iface = str_con.at("iface").value();

        if (conn != nullptr) {
            conn->set_channel(iface, channel, ht_mode);
            return;
        }

        const string chan_str = to_string(channel);
        log(LogLevel::INFO, "Setting interface " + iface + " to channel " + chan_str + " " + ht_mode);

        vector<string> cmd = {"iw", "dev", iface, "set", "channel", chan_str};
        if (!ht_mode.empty()) {
            cmd.push_back(ht_mode);
        }

        run(cmd);
    }

    void Actor_config::set_managed_mode() const{
        const string& iface = str_con.at("iface").value();
        if(conn != nullptr){conn->set_managed_mode(iface); return;}
        const optional<string> netns = str_con.at("netns");

        log(LogLevel::INFO, "Preparing interface"+iface+" for managed mode");

        run({"ip", "link", "set", iface, "down"});
        run({"iw", "dev", iface, "set", "type", "managed"});
        run({"ip", "link", "set", iface, "up"});
    }


    //TODO nejdřív napsat pořádné testy, apk optimalizavat
    void Actor_config::set_monitor_mode() const{
        const string& iface = str_con.at("iface").value();
        if(conn != nullptr){conn->set_monitor_mode(iface); return;}
        const optional<string> netns = str_con.at("netns");

        log(LogLevel::INFO, "Setting interface "+iface+" to monitor mode");

        run({"ip", "link", "set", iface, "down"});
        run({"iw", "dev", iface, "set", "type", "monitor"});
        run({"iw", "dev", iface, "set", "monitor", "fcsfail", "otherbss"});
        run({"ip", "link", "set", iface, "up"});
    }

    void Actor_config::cleanup() const {
        string iface = str_con.at("iface").value();
        optional<string> netns = str_con.at("netns");
        if (iface.empty()) {
            log(LogLevel::ERROR, "cleanup() called with empty interface name");
            return;
        }

        if (netns.has_value()) {
            log(LogLevel::INFO, "Cleaning up interface "+iface+" in netns "+*netns);

            const string phy_find_cmd = "iw dev "+iface+" info 2>/dev/null | grep wiphy | awk '{print \"phy\"$2}'";
            char buffer[128];
            string phy_name;
            FILE* pipe = popen(phy_find_cmd.c_str(), "r");
            if (pipe && fgets(buffer, sizeof(buffer), pipe)) {
                phy_name = string(buffer);
                phy_name.erase(phy_name.find_last_not_of(" \n\r\t") + 1); // trim
            }
            if (pipe) pclose(pipe);

            if (!phy_name.empty()) {
                log(LogLevel::DEBUG, "Moving "+iface+" ("+phy_name+") to netns "+*netns);
                hw_capabilities::run_cmd({"iw", "phy", phy_name, "set", "netns", "name", netns.value()}, nullopt);
            }
        } else {
            log(LogLevel::INFO, "Cleaning up interface "+iface);
        }

        // FIXME taohle by nemělo být potřeba po testu
        run({"pkill", "-f", "tshark.*" + iface});
        run({"pkill", "-f", "tcpdump.*" + iface});

        run({"rm", "-f", "/var/run/wpa_supplicant/" + iface});
        if(str_con.at("sniff_iface").has_value()){
            run({"iw", "dev", str_con.at("sniff_iface").value(), "del"});


        run({"pkill", "-f", "wpa_supplicant.*-i"+iface});
        run({"pkill", "-f", "hostapd.*"+iface});

        run({"ip", "link", "set", iface, "down"});
        run({"rfkill", "unblock", "wifi"});}
        run({"ip", "addr", "flush", "dev", iface});
        run({"ip", "link", "set", iface, "up"});
    }

    void Actor_config::create_sniff_iface() const{
        const string& iface = str_con.at("iface").value();
        const string& sniff_iface = str_con.at("sniff_iface").value();
        if(conn != nullptr){
            throw not_implemented_err("External cant have sniff_iface");
            //conn->create_sniff_iface(iface, sniff_iface); return;
        }


        string netns = "--"; //only for print
        if (str_con.contains("netns")) {netns = str_con.at("netns").value();}

        log(LogLevel::DEBUG, "Checking if %s exists in netns '%s'", sniff_iface.c_str(), netns.c_str());
        if( run({"ip", "link", "show", sniff_iface}) == 0){
            log(LogLevel::INFO, "Sniff interface %s already exists. Setting UP.", sniff_iface.c_str());
            run({"ip", "link", "set", sniff_iface, "up"});
            return;
        }

        log(LogLevel::DEBUG, "Interface %s not found, creating new one.", sniff_iface.c_str());
        const auto fd_count = distance(filesystem::directory_iterator("/proc/self/fd"),
                                      filesystem::directory_iterator{});
        log(LogLevel::DEBUG, "Current open FDs: %ld %s %s", fd_count, iface.c_str(), sniff_iface.c_str()); //FIXME sem se to d
        //run({"iw", "dev", iface, "interface", "add", sniff_iface, "type", "monitor"});
        run({"iw", "dev", iface, "interface", "add", sniff_iface, "type", "monitor","flags", "fcsfail", "otherbss"});
        run({"ip", "link", "set", sniff_iface, "up"});
    }

    int Actor_config::run(const vector<string> &argv) const{
        return hw_capabilities::run_cmd(argv, str_con.at("netns"));
    }
}
