#include "ex_program/external_actors/openwrt/OpenWrtConn.h"

#include "ex_program/ip/ip.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester {
    using namespace std;


    void OpenWrtConn::time_fix() const{
        exec("/etc/init.d/sysntpd stop");
        exec("ntpd -q -n -p 0.openwrt.pool.ntp.org");
        exec("/etc/init.d/sysntpd start");
    }

    void OpenWrtConn::forward_internet() const{
        hw_capabilities::run_cmd({"bash", "-c", "echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward"});
        hw_capabilities::run_cmd({"sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "wlan0", "-j", "MASQUERADE"});

        const string remote_ip = (*actor)["whitebox_ip"];
        const string local_iface = hw_capabilities::get_iface(remote_ip);
        const string local_ip = ip::get_ip(local_iface);

        exec("uci set network.lan.gateway=" + local_ip);
        exec("uci set network.lan.dns=8.8.8.8");
        exec("uci commit network");
        exec("/etc/init.d/network restart");
    }

    void OpenWrtConn::check_req(RunStatus& rs) const{
        exec("opkg update");
        const auto& req_programs = rs.config.at("actors")
            .at((*actor)["actor_name"]).at("setup").at("program_config").at("req_programs");

        for (const auto& program_name : req_programs) {
            exec("opkg install " + program_name.get<string>());
        }
    }

    // UCI helpers
    string OpenWrtConn::uci_get(const string& path) const {
        return exec("uci get " + path);
    }

    void OpenWrtConn::uci_set(const string& path, const string& value) const {
        exec("uci set " + path + "='" + value + "'");
        exec("uci commit");
    }

    void OpenWrtConn::get_hw_info() const{
        const string meminfo = exec("cat /proc/meminfo | grep MemTotal");
        const string cpuinfo = exec("cat /proc/cpuinfo");

        // TODO: Parse and store hardware information
    }

    void OpenWrtConn::get_openwrt_info() const{
        // Get OpenWrt version
        const string openwrt_version = exec("cat /etc/openwrt_release");

        // Get hostapd version if available
        const string hostapd_version = exec("hostapd -v 2>&1 | head -n1");

        // TODO: Parse and store OpenWrt information
    }

    OpenWrtConn::OpenWrtConn(Actor_config* actor) : ExternalConn(actor) {}

    bool OpenWrtConn::connect() {
        const bool success = ExternalConn::connect();
        if (success) {
            forward_internet();
            time_fix();
        }
        return success;
    }
}

