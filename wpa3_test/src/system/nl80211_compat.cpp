#include <fstream>
#include <string>
#include <vector>
#include <linux_headers_wifi-src/nl80211.h>
#include <linux/nl80211.h>
#include <netlink/netlink.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>

#include <iostream>
#include <net/if.h>

#include "system/hw_capabilities.h"
#include "logger/error_log.h"

namespace wpa3_tester{
    using namespace wpa3_tester;
    using namespace std;
    void check_monitor(nlattr **attrs, NlCaps *caps) {
        if (!attrs[NL80211_ATTR_SUPPORTED_IFTYPES]) {
            return;
        }

        nlattr *iftypes[NL80211_IFTYPE_MAX + 1] = {};

        nla_parse(iftypes,
                  NL80211_IFTYPE_MAX,
                  static_cast<nlattr *>(nla_data(attrs[NL80211_ATTR_SUPPORTED_IFTYPES])),
                  nla_len(attrs[NL80211_ATTR_SUPPORTED_IFTYPES]),nullptr);

        if (iftypes[NL80211_IFTYPE_MONITOR]) {caps->monitor = true;}
    }

    void check_type(nlattr **attrs, NlCaps *caps) {
        if (!attrs[NL80211_ATTR_SUPPORTED_IFTYPES]) {
            return;
        }

        nlattr *iftypes[NL80211_IFTYPE_MAX + 1] = {};

        nla_parse(iftypes,
                  NL80211_IFTYPE_MAX,
                  static_cast<nlattr *>(nla_data(attrs[NL80211_ATTR_SUPPORTED_IFTYPES])),
                  nla_len(attrs[NL80211_ATTR_SUPPORTED_IFTYPES]),nullptr);


        if (iftypes[NL80211_IFTYPE_STATION]) {caps->sta = true;}
        if (iftypes[NL80211_IFTYPE_AP]) {caps->ap = true;}
    }


    void check_WPA2_PSK(nlattr **attrs, NlCaps *caps){
        if (attrs[NL80211_ATTR_CIPHER_SUITES]) {
            const auto *ciphers = static_cast<uint32_t *>(nla_data(attrs[NL80211_ATTR_CIPHER_SUITES]));
            const int num = nla_len(attrs[NL80211_ATTR_CIPHER_SUITES]) / sizeof(uint32_t);
            for (int i = 0; i < num; i++) {
                if (ciphers[i] == 0x000FAC04) caps->wpa2_psk = true; // 00-0F-AC:4 - CCMP
            }
        }
    }
    void check_WPA3_SAE(nlattr **attrs, NlCaps *caps){
        if (attrs[NL80211_ATTR_FEATURE_FLAGS]) {
            const uint32_t feature_flags = nla_get_u32(attrs[NL80211_ATTR_FEATURE_FLAGS]);

            constexpr uint32_t NL80211_FEATURE_SAE_MASK = (1 << 5);
            if (feature_flags & NL80211_FEATURE_SAE_MASK) {
                caps->wpa3_sae = true; //Statition WPA3
            }
        }
        if (attrs[NL80211_ATTR_EXT_FEATURES]) {


            void *ext_features_data = nla_data(attrs[NL80211_ATTR_EXT_FEATURES]);
            size_t ext_features_len = nla_len(attrs[NL80211_ATTR_EXT_FEATURES]);


            constexpr uint32_t STA_BYTE_INDEX = NL80211_EXT_FEATURE_SAE_OFFLOAD / 8; // 7
            constexpr uint32_t STA_BIT_MASK = 1 << (NL80211_EXT_FEATURE_SAE_OFFLOAD % 8); // 1 << 4 (16)

            if (ext_features_len > STA_BYTE_INDEX) {
                const uint8_t target_byte = static_cast<uint8_t *>(ext_features_data)[STA_BYTE_INDEX];
                if (target_byte & STA_BIT_MASK) {
                    caps->wpa3_sae = true; //STA offload
                }
            }

            constexpr uint32_t AP_BYTE_INDEX = NL80211_EXT_FEATURE_SAE_OFFLOAD_AP / 8;
            constexpr uint32_t AP_BIT_MASK = 1 << (NL80211_EXT_FEATURE_SAE_OFFLOAD_AP % 8);

            if (ext_features_len > AP_BYTE_INDEX) {
                const uint8_t target_byte = static_cast<uint8_t *>(ext_features_data)[AP_BYTE_INDEX];
                if (target_byte & AP_BIT_MASK) {
                    caps->wpa3_sae = true;  // AP WPA3
                }
            }

        }
    }

    int hw_capabilities::nl80211_cb(nl_msg *msg, void *arg){
        auto *caps = static_cast<NlCaps *>(arg);
        const auto *gnlh = static_cast<genlmsghdr *>(nlmsg_data(nlmsg_hdr(msg)));
        nlattr *attrs[NL80211_ATTR_MAX + 1]{};

        nla_parse(attrs, NL80211_ATTR_MAX,
                  genlmsg_attrdata(gnlh, 0),
                  genlmsg_attrlen(gnlh, 0),
                  nullptr);

        check_WPA3_SAE(attrs, caps);
        check_WPA2_PSK(attrs, caps);
        check_type(attrs, caps);
        check_monitor(attrs, caps);

        return NL_SKIP;
    }


    uint32_t get_wiphy_idx_by_ifname(const std::string &ifname){
        const std::string path = "/sys/class/net/" + ifname + "/phy80211/index";
        std::ifstream file(path);
        if(uint32_t idx = 0; file >> idx) return idx;
        return 0;
    }

    void hw_capabilities::get_nl80211_caps(const std::string &iface,
                                           Actor_config &cfg){
        cfg.str_con["mac"] = read_sysfs(iface, "address");
        cfg.str_con["driver"] = get_driver_name(iface);

        /* ---------- nl80211 dynamic capabilities ---------- */
        nl_sock *sock = nl_socket_alloc();
        if(!sock){ return; }

        if(genl_connect(sock) != 0){nl_socket_free(sock);return;}

        // id of nl80211 (dynamic, ask kernel)
        const int nl80211_id = genl_ctrl_resolve(sock, "nl80211");
        if(nl80211_id < 0){nl_socket_free(sock);return;}

        // alloc message to get data from kernel
        nl_msg *msg = nlmsg_alloc();
        if(!msg){nl_socket_free(sock);return;}
        genlmsg_put(msg,
                    NL_AUTO_PORT,
                    NL_AUTO_SEQ,
                    nl80211_id,
                    0,
                    NLM_F_DUMP,
                    NL80211_CMD_GET_WIPHY,
                    0);

        // set interface id to check
        nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(iface.c_str()));

        NlCaps caps{};
        nl_socket_modify_cb(sock,
                            NL_CB_VALID,
                            NL_CB_CUSTOM,
                            &hw_capabilities::nl80211_cb,
                            &caps);

        nl_send_auto(sock, msg); // send message to kernel
        nl_recvmsgs_default(sock); // get answer

        cfg.bool_conditions["AP"] = caps.ap;
        cfg.bool_conditions["STA"] = caps.sta;
        cfg.bool_conditions["monitor"] = caps.monitor;
        cfg.bool_conditions["2_4GHz"] = caps.band24;
        cfg.bool_conditions["5GHz"] = caps.band5;

        cfg.bool_conditions["WPA-PSK"] = caps.wpa2_psk; //heuristic
        cfg.bool_conditions["WPA3-SAE"] = caps.wpa3_sae;

        nlmsg_free(msg);
        nl_socket_free(sock);
    }
}