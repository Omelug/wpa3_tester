#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <algorithm>
#include <doctest.h>
#include <vector>
#include "attacks/mc_mitm/mc_mitm.h"
#include "attacks/mc_mitm/wifi_util.h"
#include "net_parser/dot11_defs.h"
#include "pcap_helper.h"

using namespace std;
using namespace Tins;
using namespace wpa3_tester;

TEST_CASE("beacon_to_probe_resp") {
	Dot11Beacon beacon;
	beacon.addr2("aa:bb:cc:dd:ee:ff");
	beacon.addr3("aa:bb:cc:dd:ee:ff");
	beacon.interval(100);
	beacon.ds_parameter_set(6);
	beacon.ssid("TestNet");

	Channel ch{ 11, WifiBand::BAND_2_4_or_5, nullopt };
	Dot11ProbeResponse probe(beacon_to_probe_resp(beacon, ch));

	CHECK_EQ(probe.addr2(), beacon.addr2());
	CHECK_EQ(probe.addr3(), beacon.addr3());
	CHECK_EQ(probe.interval(), beacon.interval());
	CHECK_EQ(probe.ds_parameter_set(), 11);
	CHECK_NE(probe.search_option(Dot11::SSID), nullptr);
	CHECK_EQ(probe.search_option(Dot11::TIM), nullptr);
}

// ------ get_addrs
static constexpr auto PCAP_BEACON = "test_data/wifi_util/beacon.pcapng";
static HWAddress<6> BEACON_ADDR1 = "ff:ff:ff:ff:ff:ff"; // always broadcast
static HWAddress<6> BEACON_ADDR2 = "24:ec:99:bf:b0:a1"; // AP BSSID from your capture

static constexpr auto PCAP_DATA_QOS = "test_data/wifi_util/data_qos.pcapng";
static HWAddress<6> DATA_ADDR1 = "78:98:e8:55:3e:8d"; // receiver MAC
static HWAddress<6> DATA_ADDR2 = "24:ec:99:bf:e0:cd"; // transmitter MAC

static constexpr auto PCAP_CTRL_ACTION_PROTECTED = "test_data/wifi_util/action_protected.pcapng";
static HWAddress<6> ACTION_ADDR1 = "78:98:e8:55:3e:8d"; // receiver MAC (in raw bytes)
static HWAddress<6> ACTION_ADDR2 = "24:ec:99:bf:e0:cd"; // transmitter MAC (in raw bytes)

TEST_SUITE("get_addrs") {
	TEST_CASE("management frame: addr2 resolved via Dot11ManagementFrame") {
		auto [rt, raw] = test_helpers::load_frame(PCAP_BEACON);
		const auto [addr1, addr2] = get_addrs(rt, raw);

		CHECK_EQ(addr1, BEACON_ADDR1);
		CHECK_EQ(addr2, BEACON_ADDR2);
	}

	TEST_CASE("data frame: addr2 resolved via Dot11Data") {
		auto [rt, raw] = test_helpers::load_frame(PCAP_DATA_QOS);
		const auto [addr1, addr2] = get_addrs(rt, raw);

		CHECK_EQ(addr1, DATA_ADDR1);
		CHECK_EQ(addr2, DATA_ADDR2);
	}

	TEST_CASE("control frame: addr2 resolved from raw bytes fallback") {
		// RTS frame: libtins exposes no Dot11ManagementFrame/Dot11Data,
		// so addr2 falls back to raw[rt_len + 10]
		auto [rt, raw] = test_helpers::load_frame(PCAP_CTRL_ACTION_PROTECTED);
		const auto addrs = get_addrs(rt, raw);

		CHECK_EQ(addrs.addr1, ACTION_ADDR1);
		CHECK_EQ(addrs.addr2, ACTION_ADDR2);
	}

	TEST_CASE("non-Dot11 PDU returns zero addresses") {
		// plain IP packet - no Dot11 layer at all
		IP ip("1.2.3.4", "5.6.7.8");
		const auto raw = ip.serialize();
		const auto addrs = get_addrs(ip, raw);

		CHECK_EQ(addrs.addr1, HWAddress<6>());
		CHECK_EQ(addrs.addr2, HWAddress<6>());
	}
}

// --- get_eapol_msg_num
static constexpr auto PCAP_EAPOL_M1 = "test_data/wifi_util/eapol_m1.pcapng";
static constexpr auto PCAP_EAPOL_M2 = "test_data/wifi_util/eapol_m2.pcapng";
static constexpr auto PCAP_EAPOL_M3 = "test_data/wifi_util/eapol_m3.pcapng";
static constexpr auto PCAP_EAPOL_M4 = "test_data/wifi_util/eapol_m4.pcapng";

TEST_SUITE("get_eapol_msg_num") {

	TEST_CASE("M1: key_ack=1 key_mic=0 install=0 secure=0") {
		auto [rt, raw] = test_helpers::load_frame(PCAP_EAPOL_M1);
		REQUIRE(is_eapol(rt));
		CHECK_EQ(get_eapol_msg_num(raw), EapolMsg::Msg1);
	}

	TEST_CASE("M2: key_mic=1 key_ack=0 install=0 secure=0") {
		auto [rt, raw] = test_helpers::load_frame(PCAP_EAPOL_M2);
		REQUIRE(is_eapol(rt));
		CHECK_EQ(get_eapol_msg_num(raw), EapolMsg::Msg2);
	}

	TEST_CASE("M3: key_mic=1 key_ack=1 install=1 secure=1") {
		auto [rt, raw] = test_helpers::load_frame(PCAP_EAPOL_M3);
		REQUIRE(is_eapol(rt));
		CHECK_EQ(get_eapol_msg_num(raw), EapolMsg::Msg3);
	}

	TEST_CASE("M4: key_mic=1 key_ack=0 install=0 secure=1") {
		auto [rt, raw] = test_helpers::load_frame(PCAP_EAPOL_M4);
		REQUIRE(is_eapol(rt));
		CHECK_EQ(get_eapol_msg_num(raw), EapolMsg::Msg4);
	}

	TEST_CASE("non-EAPOL frame returns Unknown") {
		auto [rt, raw] = test_helpers::load_frame(PCAP_BEACON);
		CHECK_EQ(get_eapol_msg_num(raw), EapolMsg::Unknown);
	}

	TEST_CASE("bytes with no EAPOL ethertype returns Unknown") {
		IP ip("1.2.3.4", "5.6.7.8");
		CHECK_EQ(get_eapol_msg_num(ip.serialize()), EapolMsg::Unknown);
	}
}

// -----------------
// Helpers for raw 802.11 frame construction (no radiotap)

static constexpr size_t ASSOC_REQ_FIXED  = dot11::ASSOC_REQ_FIXED;
static constexpr size_t ASSOC_RESP_FIXED = dot11::ASSOC_RESP_FIXED;

static frame_raw_t mgmt_frame_with_ies(uint8_t subtype, size_t fixed_size, const frame_raw_t &ies) {
	frame_raw_t f(dot11::MGMT_HDR_SIZE + fixed_size + ies.size(), 0);
	f[0] = static_cast<uint8_t>(subtype << dot11::FC_SUBTYPE_SHIFT);
	std::copy(ies.begin(), ies.end(), f.begin() + static_cast<ptrdiff_t>(dot11::MGMT_HDR_SIZE + fixed_size));
	return f;
}

// Minimal RSN IE: version(2)+group(4)+pw_count=0+akm_count=0+caps(2)+pmkid_count+pmkids filled 0xBB
static frame_raw_t rsn_ie_with_pmkids(uint16_t pmkid_count) {
	using namespace dot11;
	const size_t data_len = RSN_VERSION_SIZE + RSN_GROUP_SIZE
	    + RSN_COUNT_SIZE + RSN_COUNT_SIZE + RSN_CAPS_SIZE
	    + RSN_COUNT_SIZE + pmkid_count * RSN_PMKID_SIZE;
	frame_raw_t ie(IE_HDR_SIZE + data_len, 0);
	ie[0] = IE_RSN;
	ie[1] = static_cast<uint8_t>(data_len);
	ie[2] = 0x01; // RSN version = 1
	constexpr size_t pmkid_off = IE_HDR_SIZE + RSN_VERSION_SIZE + RSN_GROUP_SIZE
	    + RSN_COUNT_SIZE + RSN_COUNT_SIZE + RSN_CAPS_SIZE;
	ie[pmkid_off]     = static_cast<uint8_t>(pmkid_count & 0xFF);
	ie[pmkid_off + 1] = static_cast<uint8_t>(pmkid_count >> 8);
	std::fill(ie.begin() + (pmkid_off + RSN_COUNT_SIZE), ie.end(), uint8_t{0xBB});
	return ie;
}

// -----------------

TEST_SUITE("strip_pmkid_from_rsn_ie") {
	TEST_CASE("strips PMKID when present") {
		const auto ie = rsn_ie_with_pmkids(1);
		auto frame = mgmt_frame_with_ies(dot11::MGMT_ASSOC_REQ, ASSOC_REQ_FIXED, ie);
		const size_t original_size = frame.size();
		strip_pmkid_from_rsn_ie(frame);
		CHECK_EQ(frame.size(), original_size - dot11::RSN_PMKID_SIZE);
		// PMKID count field zeroed
		constexpr size_t pmkid_count_off = dot11::MGMT_HDR_SIZE + ASSOC_REQ_FIXED
		    + dot11::IE_HDR_SIZE + dot11::RSN_VERSION_SIZE + dot11::RSN_GROUP_SIZE
		    + dot11::RSN_COUNT_SIZE + dot11::RSN_COUNT_SIZE + dot11::RSN_CAPS_SIZE;
		CHECK_EQ(frame[pmkid_count_off],     0);
		CHECK_EQ(frame[pmkid_count_off + 1], 0);
	}

	TEST_CASE("no-op when PMKID count is zero") {
		const auto ie = rsn_ie_with_pmkids(0);
		auto frame = mgmt_frame_with_ies(dot11::MGMT_ASSOC_REQ, ASSOC_REQ_FIXED, ie);
		const auto original = frame;
		strip_pmkid_from_rsn_ie(frame);
		CHECK_EQ(frame, original);
	}

	TEST_CASE("no-op when RSN IE absent") {
		auto frame = mgmt_frame_with_ies(dot11::MGMT_ASSOC_REQ, ASSOC_REQ_FIXED, {});
		const auto original = frame;
		strip_pmkid_from_rsn_ie(frame);
		CHECK_EQ(frame, original);
	}
}

TEST_SUITE("patch_ht_operation_in_frame") {
	TEST_CASE("patches primary channel byte") {
		frame_raw_t ht_ie(dot11::IE_HDR_SIZE + 22, 0); // HT Operation IE is 22 bytes of data
		ht_ie[0] = dot11::IE_HT_OPERATION;
		ht_ie[1] = 22;
		ht_ie[2] = 6; // current primary channel
		auto frame = mgmt_frame_with_ies(dot11::MGMT_ASSOC_RESP, ASSOC_RESP_FIXED, ht_ie);
		patch_ht_operation_in_frame(frame, 11);
		constexpr size_t ch_off = dot11::MGMT_HDR_SIZE + ASSOC_RESP_FIXED + dot11::IE_HDR_SIZE;
		CHECK_EQ(frame[ch_off], 11);
	}

	TEST_CASE("no-op when HT Operation IE absent") {
		auto frame = mgmt_frame_with_ies(dot11::MGMT_ASSOC_RESP, ASSOC_RESP_FIXED, {});
		const auto original = frame;
		patch_ht_operation_in_frame(frame, 11);
		CHECK_EQ(frame, original);
	}
}