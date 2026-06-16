#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <linux/nl80211.h>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include "system/hw_capabilities.h"

using namespace wpa3_tester;

struct Msg {
    nl_msg *m;
    Msg() : m(nlmsg_alloc()) {
        genlmsg_put(m, NL_AUTO_PORT, NL_AUTO_SEQ, 0, 0, 0, NL80211_CMD_NEW_WIPHY, 1);
    }
    ~Msg() { nlmsg_free(m); }
    Msg(const Msg &) = delete;
    Msg &operator=(const Msg &) = delete;
};

static NlCaps call_cb(nl_msg *msg) {
    NlCaps caps{};
    hw_capabilities::nl80211_cb(msg, &caps);
    return caps;
}

// ----------- return value + empty message

TEST_CASE("nl80211_cb - always returns NL_SKIP") {
    Msg msg;
    NlCaps caps{};
    CHECK_EQ(hw_capabilities::nl80211_cb(msg.m, &caps), NL_SKIP);
}

TEST_CASE("nl80211_cb - empty message leaves all caps false") {
    Msg msg;
    const auto caps = call_cb(msg.m);
    CHECK_FALSE(caps.monitor);
    CHECK_FALSE(caps.active_monitor);
    CHECK_FALSE(caps.ap);
    CHECK_FALSE(caps.sta);
    CHECK_FALSE(caps.csa);
    CHECK_FALSE(caps.mfp);
    CHECK_FALSE(caps.wpa2_psk);
    CHECK_FALSE(caps.wpa3_sae);
    CHECK_FALSE(caps.beacon_prot);
    CHECK_FALSE(caps.ocv);
    CHECK_EQ(caps.no_ir_24ghz, 0);
    CHECK_EQ(caps.no_ir_5ghz, 0);
    CHECK_EQ(caps.no_ir_6ghz, 0);
}

// ----------- FEATURE_FLAGS

TEST_CASE("nl80211_cb - active_monitor via NL80211_FEATURE_ACTIVE_MONITOR") {
    Msg msg;
    nla_put_u32(msg.m, NL80211_ATTR_FEATURE_FLAGS, NL80211_FEATURE_ACTIVE_MONITOR);
    const auto caps = call_cb(msg.m);
    CHECK(caps.active_monitor);
    CHECK_FALSE(caps.monitor);
}

TEST_CASE("nl80211_cb - wpa3_sae via FEATURE_FLAGS bit 5") {
    Msg msg;
    nla_put_u32(msg.m, NL80211_ATTR_FEATURE_FLAGS, 1u << 5);
    CHECK(call_cb(msg.m).wpa3_sae);
}

TEST_CASE("nl80211_cb - no flags set leaves active_monitor false") {
    Msg msg;
    nla_put_u32(msg.m, NL80211_ATTR_FEATURE_FLAGS, 0);
    CHECK_FALSE(call_cb(msg.m).active_monitor);
}

// ----------- SUPPORTED_IFTYPES

TEST_CASE("nl80211_cb - monitor via SUPPORTED_IFTYPES") {
    Msg msg;
    nlattr *nested = nla_nest_start(msg.m, NL80211_ATTR_SUPPORTED_IFTYPES);
    nla_put_flag(msg.m, NL80211_IFTYPE_MONITOR);
    nla_nest_end(msg.m, nested);
    const auto caps = call_cb(msg.m);
    CHECK(caps.monitor);
    CHECK_FALSE(caps.ap);
    CHECK_FALSE(caps.sta);
}

TEST_CASE("nl80211_cb - AP and STA via SUPPORTED_IFTYPES") {
    Msg msg;
    nlattr *nested = nla_nest_start(msg.m, NL80211_ATTR_SUPPORTED_IFTYPES);
    nla_put_flag(msg.m, NL80211_IFTYPE_AP);
    nla_put_flag(msg.m, NL80211_IFTYPE_STATION);
    nla_nest_end(msg.m, nested);
    const auto caps = call_cb(msg.m);
    CHECK(caps.ap);
    CHECK(caps.sta);
    CHECK_FALSE(caps.monitor);
}

// ----------- SUPPORTED_COMMANDS

TEST_CASE("nl80211_cb - csa when NL80211_CMD_CHANNEL_SWITCH present") {
    Msg msg;
    nlattr *nested = nla_nest_start(msg.m, NL80211_ATTR_SUPPORTED_COMMANDS);
    nla_put_u32(msg.m, 0, NL80211_CMD_CHANNEL_SWITCH);
    nla_nest_end(msg.m, nested);
    CHECK(call_cb(msg.m).csa);
}

TEST_CASE("nl80211_cb - no csa when channel switch command absent") {
    Msg msg;
    nlattr *nested = nla_nest_start(msg.m, NL80211_ATTR_SUPPORTED_COMMANDS);
    nla_put_u32(msg.m, 0, NL80211_CMD_GET_WIPHY);
    nla_nest_end(msg.m, nested);
    CHECK_FALSE(call_cb(msg.m).csa);
}

// ----------- CIPHER_SUITES

TEST_CASE("nl80211_cb - mfp via BIP-CMAC-128 cipher 0x000FAC06") {
    Msg msg;
    constexpr uint32_t cipher = 0x000FAC06;
    nla_put(msg.m, NL80211_ATTR_CIPHER_SUITES, sizeof(cipher), &cipher);
    const auto caps = call_cb(msg.m);
    CHECK(caps.mfp);
    CHECK_FALSE(caps.wpa2_psk);
}

TEST_CASE("nl80211_cb - wpa2_psk via CCMP cipher 0x000FAC04") {
    Msg msg;
    constexpr uint32_t cipher = 0x000FAC04;
    nla_put(msg.m, NL80211_ATTR_CIPHER_SUITES, sizeof(cipher), &cipher);
    const auto caps = call_cb(msg.m);
    CHECK(caps.wpa2_psk);
    CHECK_FALSE(caps.mfp);
}

TEST_CASE("nl80211_cb - both mfp and wpa2_psk from multiple ciphers") {
    Msg msg;
    constexpr uint32_t ciphers[] = {0x000FAC04, 0x000FAC06};
    nla_put(msg.m, NL80211_ATTR_CIPHER_SUITES, sizeof(ciphers), ciphers);
    const auto caps = call_cb(msg.m);
    CHECK(caps.wpa2_psk);
    CHECK(caps.mfp);
}

// ----------- EXT_FEATURES

TEST_CASE("nl80211_cb - beacon_prot via EXT_FEATURES bit") {
    Msg msg;
    constexpr int feat = NL80211_EXT_FEATURE_BEACON_PROTECTION;
    uint8_t ext[feat / 8 + 1] = {};
    ext[feat / 8] |= 1u << (feat % 8);
    nla_put(msg.m, NL80211_ATTR_EXT_FEATURES, sizeof(ext), ext);
    CHECK(call_cb(msg.m).beacon_prot);
}

TEST_CASE("nl80211_cb - ocv via EXT_FEATURES bit") {
    Msg msg;
    constexpr int feat = NL80211_EXT_FEATURE_OPERATING_CHANNEL_VALIDATION;
    uint8_t ext[feat / 8 + 1] = {};
    ext[feat / 8] |= 1u << (feat % 8);
    nla_put(msg.m, NL80211_ATTR_EXT_FEATURES, sizeof(ext), ext);
    CHECK(call_cb(msg.m).ocv);
}

TEST_CASE("nl80211_cb - EXT_FEATURES too short does not set beacon_prot") {
    Msg msg;
    constexpr int feat = NL80211_EXT_FEATURE_BEACON_PROTECTION;
    uint8_t ext[feat / 8] = {};  // exactly feat/8 bytes — index feat/8 out of range
    nla_put(msg.m, NL80211_ATTR_EXT_FEATURES, sizeof(ext), ext);
    CHECK_FALSE(call_cb(msg.m).beacon_prot);
}

TEST_CASE("nl80211_cb - wpa3_sae via SAE_OFFLOAD ext feature") {
    Msg msg;
    constexpr int feat = NL80211_EXT_FEATURE_SAE_OFFLOAD;
    uint8_t ext[feat / 8 + 1] = {};
    ext[feat / 8] |= 1u << (feat % 8);
    nla_put(msg.m, NL80211_ATTR_EXT_FEATURES, sizeof(ext), ext);
    CHECK(call_cb(msg.m).wpa3_sae);
}

// ----------- WIPHY_BANDS

TEST_CASE("nl80211_cb - band24 and 80211n via WIPHY_BANDS") {
    Msg msg;
    nlattr *bands = nla_nest_start(msg.m, NL80211_ATTR_WIPHY_BANDS);
    nlattr *band  = nla_nest_start(msg.m, 0);
        nla_put_u16(msg.m, NL80211_BAND_ATTR_HT_CAPA, 0);
        nlattr *freqs = nla_nest_start(msg.m, NL80211_BAND_ATTR_FREQS);
            nlattr *freq = nla_nest_start(msg.m, 0);
                nla_put_u32(msg.m, NL80211_FREQUENCY_ATTR_FREQ, 2412);
            nla_nest_end(msg.m, freq);
        nla_nest_end(msg.m, freqs);
    nla_nest_end(msg.m, band);
    nla_nest_end(msg.m, bands);
    const auto caps = call_cb(msg.m);
    CHECK(caps.band24);
    CHECK(caps._80211n);
    CHECK_FALSE(caps.band5);
    CHECK_FALSE(caps._80211ac);
}

TEST_CASE("nl80211_cb - band5 and 80211ac via WIPHY_BANDS") {
    Msg msg;
    nlattr *bands = nla_nest_start(msg.m, NL80211_ATTR_WIPHY_BANDS);
    nlattr *band  = nla_nest_start(msg.m, 0);
        nla_put_u32(msg.m, NL80211_BAND_ATTR_VHT_CAPA, 0);
        nlattr *freqs = nla_nest_start(msg.m, NL80211_BAND_ATTR_FREQS);
            nlattr *freq = nla_nest_start(msg.m, 0);
                nla_put_u32(msg.m, NL80211_FREQUENCY_ATTR_FREQ, 5180);
            nla_nest_end(msg.m, freq);
        nla_nest_end(msg.m, freqs);
    nla_nest_end(msg.m, band);
    nla_nest_end(msg.m, bands);
    const auto caps = call_cb(msg.m);
    CHECK(caps.band5);
    CHECK(caps._80211ac);
    CHECK_FALSE(caps.band24);
}

TEST_CASE("nl80211_cb - 80211ax via BAND_IFTYPE_DATA HE_CAP_PHY") {
    Msg msg;
    nlattr *bands    = nla_nest_start(msg.m, NL80211_ATTR_WIPHY_BANDS);
    nlattr *band     = nla_nest_start(msg.m, 0);
    nlattr *iftype_d = nla_nest_start(msg.m, NL80211_BAND_ATTR_IFTYPE_DATA);
    nlattr *entry    = nla_nest_start(msg.m, 0);
        nla_put_u8(msg.m, NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY, 0);
    nla_nest_end(msg.m, entry);
    nla_nest_end(msg.m, iftype_d);
    nla_nest_end(msg.m, band);
    nla_nest_end(msg.m, bands);
    CHECK(call_cb(msg.m)._80211ax);
}

TEST_CASE("nl80211_cb - NO_IR freq increments counter and does not set band") {
    Msg msg;
    nlattr *bands = nla_nest_start(msg.m, NL80211_ATTR_WIPHY_BANDS);
    nlattr *band  = nla_nest_start(msg.m, 0);
    nlattr *freqs = nla_nest_start(msg.m, NL80211_BAND_ATTR_FREQS);
        nlattr *freq = nla_nest_start(msg.m, 0);
            nla_put_u32(msg.m, NL80211_FREQUENCY_ATTR_FREQ, 5180);
            nla_put_flag(msg.m, NL80211_FREQUENCY_ATTR_NO_IR);
        nla_nest_end(msg.m, freq);
    nla_nest_end(msg.m, freqs);
    nla_nest_end(msg.m, band);
    nla_nest_end(msg.m, bands);
    const auto caps = call_cb(msg.m);
    CHECK_FALSE(caps.band5);
    CHECK_EQ(caps.no_ir_5ghz, 1);
}

TEST_CASE("nl80211_cb - disabled freq is skipped entirely") {
    Msg msg;
    nlattr *bands = nla_nest_start(msg.m, NL80211_ATTR_WIPHY_BANDS);
    nlattr *band  = nla_nest_start(msg.m, 0);
    nlattr *freqs = nla_nest_start(msg.m, NL80211_BAND_ATTR_FREQS);
        nlattr *freq = nla_nest_start(msg.m, 0);
            nla_put_u32(msg.m, NL80211_FREQUENCY_ATTR_FREQ, 5180);
            nla_put_flag(msg.m, NL80211_FREQUENCY_ATTR_DISABLED);
        nla_nest_end(msg.m, freq);
    nla_nest_end(msg.m, freqs);
    nla_nest_end(msg.m, band);
    nla_nest_end(msg.m, bands);
    const auto caps = call_cb(msg.m);
    CHECK_FALSE(caps.band5);
    CHECK_EQ(caps.no_ir_5ghz, 0);
}