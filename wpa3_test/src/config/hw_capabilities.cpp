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
#include <cstdlib>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace std;

int hw_capabilities::nl80211_cb(nl_msg *msg, void *arg){
    auto *caps = static_cast<NlCaps *>(arg);

    nlattr *attrs[NL80211_ATTR_MAX + 1];
    const auto gnlh = static_cast<genlmsghdr *>(nlmsg_data(nlmsg_hdr(msg)));

    nla_parse(attrs, NL80211_ATTR_MAX,
              genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), nullptr);

    // supported interface types → monitor
    if(attrs[NL80211_ATTR_SUPPORTED_IFTYPES]){
        nlattr *ift;
        int rem;
        nla_for_each_nested(ift, attrs[NL80211_ATTR_SUPPORTED_IFTYPES], rem){
            if(nla_type(ift) == NL80211_IFTYPE_MONITOR)
                caps->monitor = true;
        }
    }

    // bands
    if(attrs[NL80211_ATTR_WIPHY_BANDS]){
        nlattr *band;
        int rem;
        nla_for_each_nested(band, attrs[NL80211_ATTR_WIPHY_BANDS], rem){
            if(nla_type(band) == NL80211_BAND_2GHZ) caps->band24 = true;
            if(nla_type(band) == NL80211_BAND_5GHZ) caps->band5 = true;
        }
    }

    // AKM suites
    if(attrs[NL80211_ATTR_AKM_SUITES]){
        nlattr *akm;
        int rem;
        nla_for_each_nested(akm, attrs[NL80211_ATTR_AKM_SUITES], rem){
            const uint32_t v = nla_get_u32(akm);
            if(v == WLAN_AKM_SUITE_PSK) caps->wpa2_psk = true;
            if(v == WLAN_AKM_SUITE_SAE) caps->wpa3_sae = true;
        }
    }

    return NL_OK;
}

NlCaps hw_capabilities::get_nl80211_caps(const std::string &iface){
    NlCaps caps;

    const int ifindex = if_nametoindex(iface.c_str());
    if(!ifindex) return caps;

    nl_sock *sock = nl_socket_alloc();
    genl_connect(sock);

    const int nl80211_id = genl_ctrl_resolve(sock, "nl80211");

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

string hw_capabilities::read_sysfs(const string &iface, const string &file){
    const string path = "/sys/class/net/" + iface + "/" + file;

    ifstream ifs(path);
    if(!ifs.is_open()){
        return ""; //TODO error?
    }

    string content;
    getline(ifs, content);
    if(!content.empty() && content.back() == '\n') content.pop_back();

    return content;
}

string hw_capabilities::get_driver_name(const string &iface){
    const string path = "/sys/class/net/" + iface + "/device/driver";

    try{
        if(filesystem::exists(path) && filesystem::is_symlink(path)){
            return filesystem::read_symlink(path).filename().string();
        }
    } catch(const filesystem::filesystem_error &){
        return ""; //TODO
    }
    return "";
}


vector<InterfaceInfo> hw_capabilities::list_interfaces(const RunStatus &run_status){
    std::vector<InterfaceInfo> result;
    const filesystem::path net_path = "/sys/class/net";

    if(!exists(net_path)) return result;

    for(const auto &entry: filesystem::directory_iterator(net_path)){
        std::string name = entry.path().filename().string();

        auto ignored_list = run_status.config.value("ignore_interfaces", std::vector<std::string>{});

        if(set ignored_set(ignored_list.begin(), ignored_list.end()); ignored_set.contains(name)){
            log(LogLevel::DEBUG, "Ignoring interface %s due to ignore_interfaces config", name.c_str());
            continue;
        }

        auto type = InterfaceType::Unknown;

        // 1. Loopback ('lo')
        if(name == "lo"){
            type = InterfaceType::Loopback;
        }
        // 2. wireless Wi-Fi
        else if(filesystem::exists(entry.path() / "wireless") || filesystem::exists(entry.path() / "phy80211")){
            ifstream type_file(entry.path() / "type");
            string arp_type;
            type_file >> arp_type;

            if (arp_type == "803") {
                type = InterfaceType::WifiVirtualMon;
            } else {
                type = InterfaceType::Wifi;
            }
        }
        // 3. Docker Bridge ('bridge')
        else if(filesystem::exists(entry.path() / "bridge")){
            type = InterfaceType::DockerBridge;
        }
        // 4. VPN / TUN (tun_flags)
        else if(filesystem::exists(entry.path() / "tun_flags")){
            type = InterfaceType::VPN;
        }
        // 5.  virtual veth docker container etc)
        else if(name.find("veth") == 0){
            type = InterfaceType::VirtualVeth;
        }
        // 6. wire ethernet
        else if(filesystem::exists(entry.path() / "device")){
            type = InterfaceType::Ethernet;
        }

        result.push_back({name, type});
    }
    return result;
}

// ---------------------- BACKTRACKING ------------------------ Map of (RuleKey -> OptionKey)

bool hw_capabilities::findSolution(
    const vector<string> &ruleKeys,
    const size_t ruleIdx,
    const ActorCMap &rules,
    const ActorCMap &options,
    set<string> &usedOptions,
    AssignmentMap &currentAssignment
){
    // all set? -> solution found
    if(ruleIdx == ruleKeys.size()){ return true; }

    const string &currentRuleKey = ruleKeys[ruleIdx];
    const auto &ruleIt = rules.find(currentRuleKey);
    if(ruleIt == rules.end() || !ruleIt->second){
        throw config_error("Missing rule actor config for key: %s", currentRuleKey.c_str());
    }
    Actor_config &currentRuleReq = *ruleIt->second;

    for(auto const &[optKey, optConfigPtr]: options){
        if(!optConfigPtr){ continue; } // skip empty
        if(usedOptions.contains(optKey)){ continue; } // already used this option

        Actor_config &optConfig = *optConfigPtr;
        if(!currentRuleReq.matches(optConfig)){ continue; } // node found

        usedOptions.insert(optKey);
        currentAssignment[currentRuleKey] = optKey;

        if(findSolution(ruleKeys, ruleIdx + 1, rules, options, usedOptions, currentAssignment)){
            return true; // found in subtree
        }

        // back in tree
        usedOptions.erase(optKey);
        currentAssignment.erase(currentRuleKey);
    }

    return false; // no valid option for this rule
}

AssignmentMap hw_capabilities::check_req_options(ActorCMap &rules, const ActorCMap &options){
    vector<string> ruleKeys;
    for(const auto &key: rules | views::keys) ruleKeys.push_back(key);
    AssignmentMap result;
    if(set<string> usedOptions;
        findSolution(ruleKeys, 0, rules, options, usedOptions, result)){
        log(LogLevel::DEBUG, "Solved!");
        for(auto const &[r, o]: result){
            log(LogLevel::DEBUG, "\tActor %s -> interface %s", r.c_str(), o.c_str());
        }
        return result;
    }
    throw req_error("Not found valid requirements");
}

static int run_cmd(const std::vector<std::string> &argv){
    if(argv.empty()) return -1;

    // build C-style argv
    std::vector<char *> args;
    args.reserve(argv.size() + 1);
    for(auto &s: argv){
        args.push_back(const_cast<char *>(s.c_str()));
    }
    args.push_back(nullptr);

    const pid_t pid = fork();
    if(pid < 0){
        log(LogLevel::ERROR, "fork() failed for command %s", argv[0].c_str());
        return -1;
    }

    if(pid == 0){
        // child
        execvp(args[0], args.data());
        // if exec fails
        _exit(127);
    }

    int status = 0;
    if(waitpid(pid, &status, 0) < 0){
        log(LogLevel::ERROR, "waitpid() failed for command %s", argv[0].c_str());
        return -1;
    }

    if(!WIFEXITED(status) || WEXITSTATUS(status) != 0){
        //TODO ignore errors what say nothing changed
        //log(LogLevel::WARNING, "Command %s exited with status %d", argv[0].c_str(), WEXITSTATUS(status));
    }

    return WEXITSTATUS(status);
}

void hw_capabilities::cleanup_interface(const std::string &iface){
    log(LogLevel::INFO, "Cleaning up interface %s", iface.c_str());

    run_cmd({"pkill", "-f", "wpa_supplicant.*-i" + iface});
    run_cmd({"pkill", "-f", "hostapd.*" + iface});

    run_cmd({"ip", "link", "set", iface, "down"});

    run_cmd({"rfkill", "unblock", "wifi"}); //TODO needed here ?
    run_cmd({"ip", "addr", "flush", "dev", iface});
    run_cmd({"ip", "link", "set", iface, "up"});
}

void hw_capabilities::set_monitor_mode(const std::string &iface){
    log(LogLevel::INFO, "Setting interface %s to monitor mode", iface.c_str());

    //cleanup_interface(iface);

    run_cmd({"ip", "link", "set", iface, "down"});
    run_cmd({"iw", "dev", iface, "set", "type", "monitor"});
    run_cmd({"ip", "link", "set", iface, "up"});
}

void hw_capabilities::set_ap_mode(const std::string &iface){
    log(LogLevel::INFO, "Preparing interface %s for AP mode", iface.c_str());

    //cleanup_interface(iface);

    run_cmd({"ip", "link", "set", iface, "down"});
    run_cmd({"iw", "dev", iface, "set", "type", "managed"});
    run_cmd({"ip", "link", "set", iface, "up"});
}

void hw_capabilities::set_channel(const std::string &iface, int channel){
    log(LogLevel::INFO, "Setting interface %s to channel %d", iface.c_str(), channel);
    run_cmd({"iw", "dev", iface, "set", "channel", std::to_string(channel)});
}

int hw_capabilities::channel_to_freq_mhz(int channel){
    // 2.4 GHz band: channels 1-13 -> 2412 + 5*(ch-1), channel 14 -> 2484
    if(channel >= 1 && channel <= 13){
        return 2412 + 5 * (channel - 1);
    }
    if(channel == 14){
        return 2484;
    }

    // 5 GHz band common non-DFS channels mapping (extend as needed)
    switch(channel){
        case 36: return 5180;
        case 40: return 5200;
        case 44: return 5220;
        case 48: return 5240;
        case 52: return 5260;
        case 56: return 5280;
        case 60: return 5300;
        case 64: return 5320;
        case 100: return 5500;
        case 104: return 5520;
        case 108: return 5540;
        case 112: return 5560;
        case 116: return 5580;
        case 120: return 5600;
        case 124: return 5620;
        case 128: return 5640;
        case 132: return 5660;
        case 136: return 5680;
        case 140: return 5700;
        case 144: return 5720;
        case 149: return 5745;
        case 153: return 5765;
        case 157: return 5785;
        case 161: return 5805;
        case 165: return 5825;
        default:
            log(LogLevel::WARNING, "Unknown Wi-Fi channel %d, using 0 MHz", channel);
            return 0;
    }
}
