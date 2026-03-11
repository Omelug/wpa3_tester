#include "ex_program/external_actors/openwrt/OpenWrtConn.h"

namespace wpa3_tester {
    using namespace std;

    OpenWrtConn::OpenWrtConn(Actor_config* actor) : ExternalConn(actor) {}

    // UCI helpers
    string OpenWrtConn::uci_get(const string& path) const {
        return exec("uci get " + path);
    }

    void OpenWrtConn::uci_set(const string& path, const string& value) const {
        exec("uci set " + path + "='" + value + "'");
        exec("uci commit");
    }

    void OpenWrtConn::get_hw_info() {
        const string meminfo = exec("cat /proc/meminfo | grep MemTotal");
        const string cpuinfo = exec("cat /proc/cpuinfo");

        // TODO: Parse and store hardware information
    }

    void OpenWrtConn::get_openwrt_info() {
        // Get OpenWrt version
        const string openwrt_version = exec("cat /etc/openwrt_release");

        // Get hostapd version if available
        const string hostapd_version = exec("hostapd -v 2>&1 | head -n1");

        // TODO: Parse and store OpenWrt information
    }
}

