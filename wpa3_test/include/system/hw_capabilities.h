#pragma once

#include <netlink/netlink.h>
#include <set>
#include <string>
#include <unordered_set>
#include <vector>
#include "../config/RunStatus.h"

namespace wpa3_tester{
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
        std::string radio; // phyX
        InterfaceType type;
    };

    enum class WifiBand {
        BAND_2_4_or_5,
        BAND_2_4,
        BAND_5,
        BAND_6
    };

    inline std::string iface_to_string(const InterfaceType type) {
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
        bool sta = false;
        bool monitor = false;
        bool injection = false;

        bool band24 = false;
        bool band5 = false;
        bool band6 = false;

        bool wpa2_psk = false; // heuristic
        bool wpa3_sae = false;

        bool _80211n = false;   // 802.11n  (HT)
        bool _80211ac = false;  // 802.11ac (VHT)
        bool _80211ax= false;  // 802.11ax

        bool beacon_prot = false;
    };

    struct CryptoCaps {
        bool has_psk  = false;
        bool has_sae  = false;
        bool has_ccmp = false;
        bool has_gcmp = false;
    };

    constexpr uint32_t AKM_PSK = 0x000FAC02;
    constexpr uint32_t AKM_SAE = 0x000FAC08;

    constexpr uint32_t CIPHER_CCMP = 0x000FAC04;
    constexpr uint32_t CIPHER_GCMP_256 = 0x000FAC09;

    class hw_capabilities {
        static bool findSolution(
            const std::vector<std::string> &ruleKeys,
            size_t ruleIdx,
            const ActorCMap &rules,
            const std::vector<ActorPtr> &options,
            //only for recursive
            std::unordered_set<size_t> &usedOptions,
            ActorMap &currentAssignment
        );
        static int nl80211_cb(nl_msg *msg, void *arg);
        static void check_band_caps(nlattr *attrs[], NlCaps *caps);

    public:
        static ActorMap check_req_options(const ActorCMap &rules, const std::vector<ActorPtr> &options);
        static void run_in(const std::string &cmd, const std::filesystem::path &cwd);
        static int run_cmd(const std::vector<std::string> &argv, const std::optional<std::string> &netns = std::nullopt);
        static int freq_to_channel(int freq);
        static std::string run_cmd_output(const std::vector<std::string> &argv);

        // Fill Actor_config caps for given iface (mac, driver, nl80211 capabilities)
        static void get_nl80211_caps(const std::string &iface, Actor_config &cfg);
        static std::vector<InterfaceInfo> list_interfaces(std::optional<InterfaceType> filter = std::nullopt);

        // check availability
        static std::string read_sysfs(const std::string& iface, const std::string& file);
        static std::string get_driver_name(const std::string& iface);
        static std::string get_phy(const std::string &iface);

        //format
        static int channel_to_freq(int channel, WifiBand band= WifiBand::BAND_2_4_or_5);
        static void create_ns(const std::string& ns_name);
        static std::string rand_mac();
        static std::string get_iface(const std::string& ip_address);
    };
}