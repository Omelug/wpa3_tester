#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <vector>
#include "pcap_helper.h"
#include "attacks/mc_mitm/mc_mitm.h"

using namespace std;
using namespace Tins;
using namespace wpa3_tester;

namespace wpa3_tester{

TEST_CASE("beacon_to_probe_resp"){
    Dot11Beacon beacon;
    beacon.addr2("aa:bb:cc:dd:ee:ff");
    beacon.addr3("aa:bb:cc:dd:ee:ff");
    beacon.interval(100);
    beacon.ds_parameter_set(6);
    beacon.ssid("TestNet");

    Dot11ProbeResponse probe(beacon_to_probe_resp(beacon, 11));

    CHECK_EQ(probe.addr2(), beacon.addr2());
    CHECK_EQ(probe.addr3(), beacon.addr3());
    CHECK_EQ(probe.interval(), beacon.interval());
    CHECK_EQ(probe.ds_parameter_set(), 11);
    CHECK_NE(probe.search_option(Dot11::SSID), nullptr);
    CHECK_EQ(probe.search_option(Dot11::TIM), nullptr);
}

TEST_CASE("patch_channel_raw - beacon frame"){
    vector<uint8_t> beacon_data = test_helpers::read_pcap_file("./pcap/beacon_test.pcapng");
    vector<uint8_t> original_data = beacon_data; // Keep copy for comparison

    McMitm::patch_channel_raw(beacon_data, 11);
    PacketWriter writer("beacon_patched_result.pcap", Tins::DataLinkType<RadioTap>());
    RawPDU raw_pdu(beacon_data);
    writer.write(raw_pdu);

    // verify data was modified
    REQUIRE_NE(beacon_data, original_data);

    INFO("Beacon frame size before: " << original_data.size());
    INFO("Beacon frame size after: " << beacon_data.size());
}

// ------ get_addrs
static constexpr auto PCAP_BEACON    = "pcap/wifi_util/beacon.pcapng";
static constexpr auto BEACON_ADDR1   = "ff:ff:ff:ff:ff:ff"; // always broadcast
static constexpr auto BEACON_ADDR2   = "24:ec:99:bf:b0:a1"; // AP BSSID from your capture

static constexpr auto PCAP_DATA_QOS  = "pcap/wifi_util/data_qos.pcapng";
static constexpr auto DATA_ADDR1     = "78:98:e8:55:3e:8d"; // receiver MAC
static constexpr auto DATA_ADDR2     = "24:ec:99:bf:e0:cd"; // transmitter MAC

static constexpr auto PCAP_CTRL_ACTION_PROTECTED  = "pcap/wifi_util/action_protected.pcapng";
static constexpr auto ACTION_ADDR1   = "78:98:e8:55:3e:8d"; // receiver MAC (in raw bytes)
static constexpr auto ACTION_ADDR2   = "24:ec:99:bf:e0:cd"; // transmitter MAC (in raw bytes)

TEST_SUITE("get_addrs") {
    TEST_CASE("management frame: addr2 resolved via Dot11ManagementFrame") {
        auto [rt, raw] = test_helpers::load_frame(PCAP_BEACON);
        const auto addrs = get_addrs(rt, raw);

        CHECK_EQ(addrs.addr1.to_string(), BEACON_ADDR1);
        CHECK_EQ(addrs.addr2.to_string(), BEACON_ADDR2);
    }

    TEST_CASE("data frame: addr2 resolved via Dot11Data") {
        auto [rt, raw] = test_helpers::load_frame(PCAP_DATA_QOS);
        const auto addrs = get_addrs(rt, raw);

        CHECK_EQ(addrs.addr1.to_string(), DATA_ADDR1);
        CHECK_EQ(addrs.addr2.to_string(), DATA_ADDR2);
    }

    TEST_CASE("control frame: addr2 resolved from raw bytes fallback") {
        // RTS frame: libtins exposes no Dot11ManagementFrame/Dot11Data,
        // so addr2 falls back to raw[rt_len + 10]
        auto [rt, raw] = test_helpers::load_frame(PCAP_CTRL_ACTION_PROTECTED);
        const auto addrs = get_addrs(rt, raw);

        CHECK_EQ(addrs.addr1.to_string(), ACTION_ADDR1);
        CHECK_EQ(addrs.addr2.to_string(), ACTION_ADDR2);
    }

    TEST_CASE("non-Dot11 PDU returns zero addresses") {
        // Feed a plain IP packet — no Dot11 layer at all
        IP ip("1.2.3.4", "5.6.7.8");
        const auto raw = ip.serialize();
        const auto addrs = get_addrs(ip, raw);

        CHECK_EQ(addrs.addr1, HWAddress<6>());
        CHECK_EQ(addrs.addr2, HWAddress<6>());
    }
}

// --- get_eapol_msg_num
static constexpr auto PCAP_EAPOL_M1  = "pcap/wifi_util/eapol_m1.pcapng";
static constexpr auto PCAP_EAPOL_M2  = "pcap/wifi_util/eapol_m2.pcapng";
static constexpr auto PCAP_EAPOL_M3  = "pcap/wifi_util/eapol_m3.pcapng";
static constexpr auto PCAP_EAPOL_M4  = "pcap/wifi_util/eapol_m4.pcapng";

TEST_SUITE("get_eapol_msg_num") {

    TEST_CASE("M1: key_ack=1 key_mic=0 install=0 secure=0") {
        auto [rt, raw] = test_helpers::load_frame(PCAP_EAPOL_M1);
        REQUIRE(is_eapol(rt));
        CHECK_EQ(get_eapol_msg_num(rt), 1);
    }

    TEST_CASE("M2: key_mic=1 key_ack=0 install=0 secure=0") {
        auto [rt, raw] = test_helpers::load_frame(PCAP_EAPOL_M2);
        REQUIRE(is_eapol(rt));
        CHECK_EQ(get_eapol_msg_num(rt), 2);
    }

    TEST_CASE("M3: key_mic=1 key_ack=1 install=1 secure=1") {
        auto [rt, raw] = test_helpers::load_frame(PCAP_EAPOL_M3);
        REQUIRE(is_eapol(rt));
        CHECK_EQ(get_eapol_msg_num(rt), 3);
    }

    TEST_CASE("M4: key_mic=1 key_ack=0 install=0 secure=1") {
        auto [rt, raw] = test_helpers::load_frame(PCAP_EAPOL_M4);
        REQUIRE(is_eapol(rt));
        CHECK_EQ(get_eapol_msg_num(rt), 4);
    }

    TEST_CASE("non-EAPOL frame returns -1") {
        // Beacon has no RSNEAPOL layer
        auto [rt, raw] = test_helpers::load_frame(PCAP_BEACON);
        CHECK_EQ(get_eapol_msg_num(rt), -1);
    }

    TEST_CASE("plain PDU with no RSNEAPOL returns -1") {
        IP ip("1.2.3.4", "5.6.7.8");
        CHECK_EQ(get_eapol_msg_num(ip), -1);
    }
}

}