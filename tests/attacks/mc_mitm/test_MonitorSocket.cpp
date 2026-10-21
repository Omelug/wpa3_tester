#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include "attacks/mc_mitm/MonitorSocket.h"
#include "attacks/mc_mitm/wifi_util.h"
#include "pcap_helper.h"
#include "system/hw_capabilities.h"

using namespace std;
using namespace Tins;
using namespace wpa3_tester;

static constexpr auto PCAP_NO_FCS = "test_data/monitor_socket/radiotap_no_fcs.pcapng";
static constexpr auto PCAP_WITH_FCS = "test_data/monitor_socket/radiotap_with_fcs.pcapng";
static constexpr auto PCAP_MULTI = "test_data/monitor_socket/radiotap_multi.pcapng";

// ------- unit tests ---------

TEST_SUITE("MonitorSocket::parse_frame") {

	TEST_CASE("valid RadioTap frame (no FCS) returns non-null PDU") {
		frame_raw_t raw = test_helpers::read_one_frame(PCAP_NO_FCS);
		auto result = MonitorSocket::parse_frame(raw);

		REQUIRE_UNARY(static_cast<bool>(result));
		REQUIRE_NE(result.pdu, nullptr);
		CHECK_UNARY_FALSE(result.raw.empty());
	}

	TEST_CASE("raw bytes match input size when no FCS present") {
		frame_raw_t raw = test_helpers::read_one_frame(PCAP_NO_FCS);
		auto result = MonitorSocket::parse_frame(raw);

		CHECK_EQ(result.raw.size(), raw.size());
	}

	TEST_CASE("FCS strip: raw output is 4 bytes shorter than input") {
		frame_raw_t raw = test_helpers::read_one_frame(PCAP_WITH_FCS);
		auto result = MonitorSocket::parse_frame(raw);

		REQUIRE_NE(result.pdu, nullptr);
		CHECK_EQ(result.raw.size(), raw.size() - 4);
	}

	TEST_CASE("parsed PDU contains a RadioTap layer") {
		auto raw = test_helpers::read_one_frame(PCAP_NO_FCS);
		auto result = MonitorSocket::parse_frame(raw);

		REQUIRE_NE(result.pdu, nullptr);
		CHECK_NE(result.pdu->find_pdu<RadioTap>(), nullptr);
	}

	TEST_CASE("garbage bytes return empty result") {
		const frame_raw_t garbage = { 0x00, 0xFF, 0xAA, 0x42 };
		auto result = MonitorSocket::parse_frame(garbage);
		CHECK_UNARY_FALSE(static_cast<bool>(result));
		CHECK_EQ(result.pdu, nullptr);
	}

	TEST_CASE("zero caplen returns empty result") {
		constexpr frame_raw_t raw = {};
		auto result = MonitorSocket::parse_frame(raw);
		CHECK_UNARY_FALSE(static_cast<bool>(result));
	}
}

TEST_SUITE("MonitorSocket::build_inject_frame") {

	TEST_CASE("too short input returns empty") {
		const vector<uint8_t> short_buf = { 0x00, 0x00 };
		Channel ch{ 6, WifiBand::BAND_2_4, nullopt };
		const auto out = MonitorSocket::build_inject_frame(short_buf, ch);
		CHECK_UNARY(out.empty());
	}

	TEST_CASE("rt_len larger than buffer returns empty") {
		// bytes 2-3 claim rt_len = 0xFFFF
		const vector<uint8_t> bad = { 0x00, 0x00, 0xFF, 0xFF, 0xAA, 0xBB };
		Channel ch{ 6, WifiBand::BAND_2_4, nullopt };
		const auto out = MonitorSocket::build_inject_frame(bad, ch);
		CHECK_UNARY(out.empty());
	}

	TEST_CASE("payload after old RadioTap is preserved byte-for-byte") {
		frame_raw_t raw = test_helpers::read_one_frame(PCAP_NO_FCS);
		const uint16_t rt_len = raw[2] | (static_cast<uint16_t>(raw[3]) << 8);

		Channel ch{ 6, WifiBand::BAND_2_4, nullopt };
		const auto out = MonitorSocket::build_inject_frame(raw, ch);
		REQUIRE_UNARY_FALSE(out.empty());

		const uint16_t new_rt_len = out[2] | static_cast<uint16_t>(out[3]) << 8;
		const vector old_payload(raw.begin() + rt_len, raw.end());
		// libtins RadioTap{} sets FCS flag → appends 4-byte FCS; strip before comparing
		REQUIRE_GE(out.size(), static_cast<size_t>(new_rt_len) + 4);
		const vector new_payload(out.begin() + new_rt_len, out.end() - 4);

		REQUIRE_EQ(old_payload.size(), new_payload.size());
		CHECK_EQ(old_payload, new_payload);
	}

// -- Sequence test: multiple frames from a single pcap file ---

	TEST_SUITE("MonitorSocket::parse_frame sequence") {

		TEST_CASE("all frames in multi-frame pcap parse without error") {
			const auto frames = test_helpers::read_all_frames(PCAP_MULTI);
			REQUIRE_UNARY_FALSE(frames.empty());

			for(const auto &raw: frames) {
				auto result = MonitorSocket::parse_frame(raw);
				CHECK_NE(result.pdu, nullptr);
			}
		}
}
}

// -----------------

static vector<uint8_t> make_assoc_req_raw(const string &ssid) {
	Dot11AssocRequest req;
	req.addr1(HWAddress<6>("ff:ff:ff:ff:ff:ff"));
	req.addr2(HWAddress<6>("aa:bb:cc:dd:ee:ff"));
	req.addr3(HWAddress<6>("11:22:33:44:55:66"));
	req.capabilities().ess(true);
	req.capabilities().privacy(true);
	req.capabilities().short_preamble(true);
	req.capabilities().sst(true);
	req.listen_interval(10);
	req.add_option({ Dot11::SSID, static_cast<uint8_t>(ssid.size()),
		reinterpret_cast<const uint8_t *>(ssid.data()) });
	return req.serialize();
}

static string ssid_from_raw(const frame_raw_t &raw) {
	const uint16_t rt_len_raw = static_cast<uint16_t>(raw[2]) | (static_cast<uint16_t>(raw[3]) << 8);
	const size_t rt_off = (raw[0] == 0 && rt_len_raw >= 8 && raw.size() >= rt_len_raw) ? rt_len_raw : 0;
	const Dot11AssocRequest req(raw.data() + rt_off, raw.size() - rt_off);
	const auto *opt = req.search_option(Dot11::SSID);
	if(!opt) return "";
	return { reinterpret_cast<const char *>(opt->data_ptr()), opt->data_size() };
}

static frame_raw_t make_beacon_raw(const string &ssid) {
	Dot11Beacon beacon;
	beacon.addr1(HWAddress<6>("ff:ff:ff:ff:ff:ff"));
	beacon.addr2(HWAddress<6>("aa:bb:cc:dd:ee:ff"));
	beacon.addr3(HWAddress<6>("aa:bb:cc:dd:ee:ff"));
	beacon.add_option({ Dot11::SSID, static_cast<uint8_t>(ssid.size()),
		reinterpret_cast<const uint8_t *>(ssid.data()) });
	return beacon.serialize();
}

static string ssid_from_beacon_raw(const frame_raw_t &raw) {
	const Dot11Beacon b(raw.data(), raw.size());
	const auto *opt = b.search_option(Dot11::SSID);
	if(!opt) return "";
	return { reinterpret_cast<const char *>(opt->data_ptr()), opt->data_size() };
}

TEST_SUITE("rewrite_ssid_in_frame") {

	TEST_CASE("replaces SSID in bare AssocRequest") {
		auto raw = make_assoc_req_raw("SafeNet");
		rewrite_ssid_in_frame(raw, "WrongNet");
		CHECK_EQ(ssid_from_raw(raw), "WrongNet");
	}

	TEST_CASE("replaces SSID when RadioTap header is present") {
		auto bare = make_assoc_req_raw("SafeNet");
		auto raw = ensure_radiotap(bare);
		rewrite_ssid_in_frame(raw, "WrongNet");
		CHECK_EQ(ssid_from_raw(raw), "WrongNet");
	}

	TEST_CASE("replaces SSID in Beacon frame (subtype 8, 12-byte fixed fields)") {
		auto raw = make_beacon_raw("SafeNet");
		rewrite_ssid_in_frame(raw, "WrongNet");
		CHECK_EQ(ssid_from_beacon_raw(raw), "WrongNet");
	}

	TEST_CASE("no-op when malformed IE precedes SSID") {
		// bare AssocRequest: 24B mgmt hdr + 4B fixed fields
		// IEs: SupportedRates(valid) + VendorIE(len=200, only 1 byte present) + SSID(unreachable)
		vector<uint8_t> frame(28, 0x00); // FC=0x00 (AssocRequest subtype 0)
		const vector<uint8_t> ies = {
			0x01, 0x01, 0x82,                            // SupportedRates: ok
			0xDD, 200, 0xAA,                             // VendorIE: len=200, only 1 byte (malformed)
			0x00, 0x07, 'S','a','f','e','N','e','t',     // SSID: unreachable
		};
		frame.insert(frame.end(), ies.begin(), ies.end());
		const auto orig = frame;
		rewrite_ssid_in_frame(frame, "WrongNet");
		CHECK_EQ(frame, orig);
	}

	TEST_CASE("truncates new SSID to 32 bytes") {
		auto raw = make_assoc_req_raw("SafeNet");
		const string long_ssid(40, 'X');
		rewrite_ssid_in_frame(raw, long_ssid);
		CHECK_EQ(ssid_from_raw(raw).size(), 32u);
	}

	TEST_CASE("no-op on frame too short to contain IEs") {
		vector<uint8_t> tiny = { 0x00, 0x04, 0xFF, 0xFF };
		const auto orig = tiny;
		rewrite_ssid_in_frame(tiny, "WrongNet");
		CHECK_EQ(tiny, orig);
	}
}

// -----------------

TEST_SUITE("ensure_radiotap") {

	TEST_CASE("idempotent on frame that already has RadioTap") {
		frame_raw_t raw = test_helpers::read_one_frame(PCAP_NO_FCS);
		const auto once = ensure_radiotap(raw);
		const auto twice = ensure_radiotap(once);
		CHECK_EQ(once, twice);
	}

	TEST_CASE("adds RadioTap to bare 802.11 frame; second call is no-op") {
		frame_raw_t raw = test_helpers::read_one_frame(PCAP_NO_FCS);
		const uint16_t rt_len = raw[2] | static_cast<uint16_t>(raw[3]) << 8;
		const vector bare(raw.begin() + rt_len, raw.end());

		const auto with_rt = ensure_radiotap(bare);
		CHECK_NE(with_rt, bare);
		CHECK_EQ(with_rt[0], 0x00); // RadioTap revision byte
		CHECK_EQ(ensure_radiotap(with_rt), with_rt);
	}

	TEST_CASE("invalid frame type (FC type=3) throws") {
		CHECK_THROWS(ensure_radiotap({ 0xFF, 0xFF, 0xFF, 0xFF }));
	}
}