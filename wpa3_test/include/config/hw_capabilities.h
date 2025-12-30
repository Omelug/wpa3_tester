#pragma once

#include <netlink/netlink.h>
#include <set>
#include <string>
#include <vector>

#include "RunStatus.h"

#define WLAN_AKM_SUITE_PSK 0x000FAC02
#define WLAN_AKM_SUITE_SAE 0x000FAC08

enum class InterfaceType {
    Unknown,
    Loopback,
    Wifi,
    Ethernet,
    DockerBridge,
    VirtualVeth,
    VPN,
    WifiVirtualMon
};

struct InterfaceInfo {
    std::string name;
    InterfaceType type;
};

inline std::string to_string(const InterfaceType type) {
    switch (type) {
        case InterfaceType::Loopback:       return "loopback";
        case InterfaceType::Wifi:           return "wifi";
        case InterfaceType::Ethernet:       return "ethernet";
        case InterfaceType::DockerBridge:   return "docker/bridge";
        case InterfaceType::VirtualVeth:    return "veth";
        case InterfaceType::VPN:            return "vpn";
        case InterfaceType::WifiVirtualMon: return "wifi-virtual-mon";
        default:                            return "unknown";
    }
}
struct NlCaps {
    bool ap = false;
    bool monitor = false;
    bool band24 = false;
    bool band5 = false;
    bool wpa2_psk = false;
    bool wpa3_sae = false;
};

class hw_capabilities {
    /* find solution of actors and available interfaces */
    static bool findSolution(
        const std::vector<std::string>& ruleKeys,
        size_t ruleIdx,
        const ActorCMap& rules,
        const ActorCMap& options,
        //only for recursive
        std::set<std::string>& usedOptions,
        AssignmentMap& currentAssignment
    );
    static int nl80211_cb(nl_msg *msg, void *arg);

public:
    static AssignmentMap check_req_options(ActorCMap& rules, const ActorCMap& options);

    // Fill Actor_config caps for given iface (mac, driver, nl80211 capabilities)
    static void get_nl80211_caps(const std::string &iface, Actor_config &cfg);

    static std::vector<InterfaceInfo> list_interfaces(const RunStatus& run_status);

    // check availability
    static std::string read_sysfs(const std::string& iface, const std::string& file);
    static std::string get_driver_name(const std::string& iface);

    // setup requirements
    static void cleanup_interface(const std::string& iface);
    static void set_monitor_mode(const std::string& iface);
    static void set_ap_mode(const std::string& iface);
    static void set_channel(const std::string& iface, int channel);

    //format
    static int channel_to_freq_mhz(int channel);

};
