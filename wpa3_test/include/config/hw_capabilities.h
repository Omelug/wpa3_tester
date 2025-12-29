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
    bool monitor = false;
    bool band24 = false;
    bool band5 = false;
    bool wpa2_psk = false;
    bool wpa3_sae = false;
};

class hw_capabilities {
public:
    static bool findSolution(
        const std::vector<std::string>& ruleKeys,
        size_t ruleIdx,
        const ActorCMap& rules,
        const ActorCMap& options,
        std::set<std::string>& usedOptions,
        AssignmentMap& currentAssignment
    );

    static AssignmentMap check_req_options(ActorCMap& rules, const ActorCMap& options);

    static int nl80211_cb(nl_msg *msg, void *arg);
    static NlCaps get_nl80211_caps(const std::string& iface);

    static std::string read_sysfs(const std::string& iface, const std::string& file);
    static std::string get_driver_name(const std::string& iface);
    static std::vector<InterfaceInfo> list_interfaces(const RunStatus& run_status);
    static void cleanup_interface(const std::string& iface);
    static void set_monitor_mode(const std::string& iface);
    static void set_ap_mode(const std::string& iface);
    static void set_channel(const std::string& iface, int channel);
    static int channel_to_freq_mhz(int channel);
};
