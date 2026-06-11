#pragma once
#include <array>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace wpa3_tester {

struct Driver {
	std::optional<std::string> driver_name;
	std::optional<std::string> driver_hash;   // /sys/module/<name>/srcversion
	std::optional<std::string> module_hash;   // combined hash of driver + all depends srcversions
};

// String keys
enum class SK : uint8_t {
    actor_name, source, iface, mac, permanent_mac, ssid, channel,
    signal, ht_mode, driver_name, driver_hash, module_hash, netns, sniff_iface,
    radio, whitebox_host, whitebox_ip, ip_addr,
    ssh_user, ssh_port, ssh_password, external_OS,
    COUNT_
};

// Bool keys
enum class BK : uint8_t {
    AP, STA, injection_selftest, monitor, managed,
    active_monitor, control_monitor,
    GHz2_4, GHz5, GHz6,
    w80211n, w80211ac, w80211ax, beacon_prot,
    CSA, OCV, MFP, WPA_PSK, WPA3_SAE,
    COUNT_
};


// Name arrays — must match enum order exactly, compile-time size verified by COUNT_

inline constexpr std::array<std::string_view, static_cast<size_t>(SK::COUNT_)> SK_NAMES = {
    "actor_name", "source", "iface", "mac", "permanent_mac", "ssid", "channel",
    "signal", "ht_mode", "driver", "driver_hash", "module_hash", "netns", "sniff_iface",
    "radio", "whitebox_host", "whitebox_ip", "ip_addr",
    "ssh_user", "ssh_port", "ssh_password", "external_OS"
};

inline constexpr std::array<std::string_view, static_cast<size_t>(BK::COUNT_)> BK_NAMES = {
    "AP", "STA", "injection_selftest", "monitor", "managed",
    "active_monitor", "control_monitor" ,
    "2_4GHz", "5GHz", "6GHz",
    "80211n", "80211ac", "80211ax", "beacon_prot",
    "CSA", "OCV", "MFP", "WPA-PSK", "WPA3-SAE",
};


constexpr std::string_view sk_name(SK k) {
    return SK_NAMES[static_cast<size_t>(k)];
}

constexpr std::string_view bk_name(BK k) {
    return BK_NAMES[static_cast<size_t>(k)];
}

constexpr std::optional<SK> sk_cast(const std::string_view name) {
    for(size_t i = 0; i < SK_NAMES.size(); ++i)
        if(SK_NAMES[i] == name)
        	return static_cast<SK>(i);
    return std::nullopt;
}

constexpr std::optional<BK> bk_cast(const std::string_view name) {
    for(size_t i = 0; i < BK_NAMES.size(); ++i)
        if(BK_NAMES[i] == name) return static_cast<BK>(i);
    return std::nullopt;
}


constexpr auto sk_values() {
    std::array<SK, static_cast<size_t>(SK::COUNT_)> arr{};
    for(size_t i = 0; i < arr.size(); ++i) arr[i] = static_cast<SK>(i);
    return arr;
}

constexpr auto bk_values() {
    std::array<BK, static_cast<size_t>(BK::COUNT_)> arr{};
    for(size_t i = 0; i < arr.size(); ++i) arr[i] = static_cast<BK>(i);
    return arr;
}


using ParamFilter = std::pair<std::vector<SK>, std::vector<BK>>;

class ActorPtr;
using ActorCMap = std::unordered_map<std::string, ActorPtr>;

}