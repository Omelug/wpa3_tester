#pragma once

#include <net/if.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <linux/nl80211.h>
#include <set>
#include <string>
#include <vector>

#include "RunStatus.h"

#define WLAN_AKM_SUITE_PSK 0x000FAC02
#define WLAN_AKM_SUITE_SAE 0x000FAC08

struct NlCaps {
    bool monitor = false;
    bool band24 = false;
    bool band5 = false;
    bool wpa2_psk = false;
    bool wpa3_sae = false;
};

class hw_capabilities {
public:
    static void ensure_iw_cached();
    static std::string run_command(const std::string &cmd);
    static std::string get_iw_cache();
    static std::string get_phy_from_iface(const std::string &iface);
    static void reset();
    static bool findSolution(
        const std::vector<std::string>& ruleKeys,
        size_t ruleIdx,
        const ActorCMap& rules,
        const ActorCMap& options,
        std::set<std::string>& usedOptions,
        AssignmentMap& currentAssignment
    );

    static AssignmentMap check_req_options(ActorCMap& rules, const ActorCMap& options);

    static int nl80211_cb(struct nl_msg *msg, void *arg);
    static NlCaps get_nl80211_caps(const std::string& iface);

    static std::string read_sysfs(const std::string& iface, const std::string& file);
    static std::string get_driver_name(const std::string& iface);
    static std::vector<std::string> list_interfaces();
};
