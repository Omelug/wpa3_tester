#include "config/hw_capabilities.h"
#include "config/RunStatus.h"
#include "logger/error_log.h"
#include "logger/log.h"

#include <net/if.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <linux/nl80211.h>

#include <string>
#include <cstdio>
#include <map>
#include <set>
#include <vector>
#include <fstream>

using namespace std;



int hw_capabilities::nl80211_cb(struct nl_msg *msg, void *arg) {
    auto *caps = static_cast<NlCaps*>(arg);

    nlattr *attrs[NL80211_ATTR_MAX + 1];
    genlmsghdr *gnlh = (genlmsghdr*) nlmsg_data(nlmsg_hdr(msg));

    nla_parse(attrs, NL80211_ATTR_MAX,
              genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), nullptr);

    // supported iftypes → monitor
    if (attrs[NL80211_ATTR_SUPPORTED_IFTYPES]) {
        nlattr *ift;
        int rem;
        nla_for_each_nested(ift, attrs[NL80211_ATTR_SUPPORTED_IFTYPES], rem) {
            if (nla_type(ift) == NL80211_IFTYPE_MONITOR)
                caps->monitor = true;
        }
    }

    // bands
    if (attrs[NL80211_ATTR_WIPHY_BANDS]) {
        nlattr *band;
        int rem;
        nla_for_each_nested(band, attrs[NL80211_ATTR_WIPHY_BANDS], rem) {
            if (nla_type(band) == NL80211_BAND_2GHZ) caps->band24 = true;
            if (nla_type(band) == NL80211_BAND_5GHZ) caps->band5 = true;
        }
    }

    // AKM suites
    if (attrs[NL80211_ATTR_AKM_SUITES]) {
        nlattr *akm;
        int rem;
        nla_for_each_nested(akm, attrs[NL80211_ATTR_AKM_SUITES], rem) {
            uint32_t v = nla_get_u32(akm);
            if (v == WLAN_AKM_SUITE_PSK) caps->wpa2_psk = true;
            if (v == WLAN_AKM_SUITE_SAE) caps->wpa3_sae = true;
        }
    }

    return NL_OK;
}

NlCaps hw_capabilities::get_nl80211_caps(const std::string& iface) {
    NlCaps caps;

    int ifindex = if_nametoindex(iface.c_str());
    if (!ifindex) return caps;

    nl_sock *sock = nl_socket_alloc();
    genl_connect(sock);

    int nl80211_id = genl_ctrl_resolve(sock, "nl80211");

    nl_msg *msg = nlmsg_alloc();
    genlmsg_put(msg, 0, 0, nl80211_id, 0, 0,
                NL80211_CMD_GET_WIPHY, 0);

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex);

    nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM,
                        nl80211_cb, &caps);

    nl_send_auto(sock, msg);
    nl_recvmsgs_default(sock);

    nlmsg_free(msg);
    nl_socket_free(sock);

    return caps;
}

string hw_capabilities::read_sysfs(const string& iface, const string& file) {
    // Cesta vypadá např. takto: /sys/class/net/wlan0/address
    string path = "/sys/class/net/" + iface + "/" + file;

    ifstream ifs(path);
    if (!ifs.is_open()) {
        return ""; //TODO error?
    }

    string content;
    getline(ifs, content);
    if (!content.empty() && content.back() == '\n') content.pop_back();

    return content;
}
string hw_capabilities::get_driver_name(const string& iface) {
    string path = "/sys/class/net/" + iface + "/device/driver";

    try {
        if (filesystem::exists(path) && filesystem::is_symlink(path)) {
            return filesystem::read_symlink(path).filename().string();
        }
    } catch (const filesystem::filesystem_error& e) {
        return "";
    }
    return "";
}
vector<string> hw_capabilities::list_interfaces() {
    vector<string> result;
    for (auto &p : filesystem::directory_iterator("/sys/class/net")) {
        result.push_back(p.path().filename());
    }
    return result;
}


// ---------------------- BACKTRACKING ------------------------ Map of (RuleKey -> OptionKey)

bool hw_capabilities::findSolution(
    const vector<string>& ruleKeys,
    const size_t ruleIdx,
    const ActorCMap& rules,
    const ActorCMap& options,
    set<string>& usedOptions,
    AssignmentMap& currentAssignment
){
    // all set? -> solution found
    if (ruleIdx == ruleKeys.size()) {return true;}

    const string& currentRuleKey = ruleKeys[ruleIdx];
    const auto &ruleIt = rules.find(currentRuleKey);
    if (ruleIt == rules.end() || !ruleIt->second) {
        throw config_error("Missing rule actor config for key: %s", currentRuleKey.c_str());
    }
    Actor_config& currentRuleReq = *ruleIt->second;

    for (auto const& [optKey, optConfigPtr] : options) {
        if (!optConfigPtr) {continue;} // skip empty
        if (usedOptions.contains(optKey)) {continue;} // already used this option

        Actor_config& optConfig = *optConfigPtr;
        if (!currentRuleReq.matches(optConfig)) {continue;} // node found

        usedOptions.insert(optKey);
        currentAssignment[currentRuleKey] = optKey;

        if (findSolution(ruleKeys, ruleIdx + 1, rules, options, usedOptions, currentAssignment)) {
            return true; // found in sub-tree
        }

        // back in tree
        usedOptions.erase(optKey);
        currentAssignment.erase(currentRuleKey);
    }

    return false; // no valid option for this rule
}

AssignmentMap hw_capabilities::check_req_options(ActorCMap& rules, const ActorCMap& options) {
    vector<string> ruleKeys;
    for (const auto &key: rules | views::keys) ruleKeys.push_back(key);

    AssignmentMap result;
    if (set<string> usedOptions;
        findSolution(ruleKeys, 0, rules, options, usedOptions, result)) {
        log(LogLevel::DEBUG, "Solved!");
        for (auto const& [r, o] : result) {
            log(LogLevel::DEBUG, "\tActor %s -> interface %s", r.c_str(), o.c_str());
        }

		//set options properties to result
        for (auto &ruleEntry : rules) {
            const string &actorName = ruleEntry.first;
            auto resIt = result.find(actorName);
            if (resIt == result.end()) {continue;}

            const string &optKey = resIt->second;
            auto optIt = options.find(optKey);
            if (optIt == options.end() || !optIt->second) {
                throw config_error("Selected option %s for actor %s not found in options", optKey.c_str(), actorName.c_str());
            }
            ruleEntry.second = make_unique<Actor_config>(*optIt->second);
        }

        return result;
    }
    throw req_error("Not found valid requirements");
}