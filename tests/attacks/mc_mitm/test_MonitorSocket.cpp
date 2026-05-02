#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include "pcap_helper.h"
#include "attacks/mc_mitm/MonitorSocket.h"
#include "system/hw_capabilities.h"

using namespace std;
using namespace Tins;
using namespace wpa3_tester;

static constexpr auto PCAP_NO_FCS   = "pcap/monitor_socket/radiotap_no_fcs.pcapng";
static constexpr auto PCAP_WITH_FCS = "pcap/monitor_socket/radiotap_with_fcs.pcapng";
static constexpr auto PCAP_MULTI    = "pcap/monitor_socket/radiotap_multi.pcapng";

// ------- unit tests ---------

TEST_SUITE("MonitorSocket::parse_frame") {

    TEST_CASE("valid RadioTap frame (no FCS) returns non-null PDU") {
        auto [hdr, raw] = test_helpers::read_one_frame(PCAP_NO_FCS);
        auto result = MonitorSocket::parse_frame(raw.data(), hdr.caplen);

        REQUIRE_UNARY(static_cast<bool>(result));
        REQUIRE_NE(result.pdu, nullptr);
        CHECK_UNARY_FALSE(result.raw.empty());
    }

    TEST_CASE("raw bytes match input size when no FCS present") {
        auto [hdr, raw] = test_helpers::read_one_frame(PCAP_NO_FCS);
        auto result = MonitorSocket::parse_frame(raw.data(), hdr.caplen);

        CHECK_EQ(result.raw.size(), raw.size());
    }

    TEST_CASE("FCS strip: raw output is 4 bytes shorter than input") {
        auto [hdr, raw] = test_helpers::read_one_frame(PCAP_WITH_FCS);
        auto result = MonitorSocket::parse_frame(raw.data(), hdr.caplen);

        REQUIRE_NE(result.pdu, nullptr);
        CHECK_EQ(result.raw.size(), raw.size() - 4);
    }

    TEST_CASE("parsed PDU contains a RadioTap layer") {
        auto [hdr, raw] = test_helpers::read_one_frame(PCAP_NO_FCS);
        auto result = MonitorSocket::parse_frame(raw.data(), hdr.caplen);

        REQUIRE_NE(result.pdu, nullptr);
        CHECK_NE(result.pdu->find_pdu<RadioTap>(), nullptr);
    }

    TEST_CASE("garbage bytes return empty result") {
        const std::vector<uint8_t> garbage = {0x00, 0xFF, 0xAA, 0x42};
        auto result = MonitorSocket::parse_frame(garbage.data(),
                                                 static_cast<uint32_t>(garbage.size()));
        CHECK_UNARY_FALSE(static_cast<bool>(result));
        CHECK_EQ(result.pdu, nullptr);
    }

    TEST_CASE("zero caplen returns empty result") {
        const std::vector<uint8_t> raw = {0x00};
        auto result = MonitorSocket::parse_frame(raw.data(), 0);
        CHECK_UNARY_FALSE(static_cast<bool>(result));
    }
}

TEST_SUITE("MonitorSocket::build_inject_frame") {

    TEST_CASE("too short input returns empty") {
        const std::vector<uint8_t> short_buf = {0x00, 0x00};
        const auto out = MonitorSocket::build_inject_frame(short_buf, 6);
        CHECK_UNARY(out.empty());
    }

    TEST_CASE("rt_len larger than buffer returns empty") {
        // bytes 2-3 claim rt_len = 0xFFFF
        const std::vector<uint8_t> bad = {0x00, 0x00, 0xFF, 0xFF, 0xAA, 0xBB};
        const auto out = MonitorSocket::build_inject_frame(bad, 6);
        CHECK_UNARY(out.empty());
    }

    /*TEST_CASE("output starts with valid RadioTap header") {
        auto [hdr, raw] = test_helpers::read_one_frame(PCAP_NO_FCS);
        const auto out = MonitorSocket::build_inject_frame({raw.begin(), raw.end()}, 6);

        REQUIRE_UNARY_FALSE(out.empty());
        // RadioTap revision byte must be 0
        CHECK_EQ(out[0], 0x00);
        // Deserialize and verify channel
        RadioTap rt(out.data(), out.size());
        CHECK_EQ(rt.channel_freq(), hw_capabilities::channel_to_freq(6));
    }*/

    TEST_CASE("payload after old RadioTap is preserved byte-for-byte") {
        auto [hdr, raw] = test_helpers::read_one_frame(PCAP_NO_FCS);
        const uint16_t rt_len = raw[2] | (static_cast<uint16_t>(raw[3]) << 8);

        const auto out = MonitorSocket::build_inject_frame(raw, 6);
        REQUIRE_UNARY_FALSE(out.empty());

        const std::vector old_payload(raw.begin() + rt_len, raw.end());
        const std::vector new_payload(out.begin() + rt_len, out.end());

        //payload is unmodified
        REQUIRE_EQ(old_payload.size(), new_payload.size());
        CHECK_EQ(old_payload, new_payload);
    }

    TEST_CASE("detect_injected sets More Data bit in FC field") {
        auto [hdr, raw] = test_helpers::read_one_frame(PCAP_NO_FCS);
        const auto out = MonitorSocket::build_inject_frame(
            {raw.begin(), raw.end()}, 6, /*detect_injected=*/true);

        REQUIRE_UNARY_FALSE(out.empty());

        RadioTap rt_check{};
        rt_check.channel(hw_capabilities::channel_to_freq(6), RadioTap::OFDM);
        const auto new_rt_len = rt_check.serialize().size();
        REQUIRE_GT(out.size(), new_rt_len + 1u);

        CHECK_EQ(out[new_rt_len + 1] & 0x20, 0x20); // More Data bit
    }
}

// -- Sequence test: multiple frames from a single pcap file ---

TEST_SUITE("MonitorSocket::parse_frame sequence") {

    TEST_CASE("all frames in multi-frame pcap parse without error") {
        const auto frames = test_helpers::read_all_frames(PCAP_MULTI);
        REQUIRE_UNARY_FALSE(frames.empty());

        for (const auto &raw : frames) {
            auto result = MonitorSocket::parse_frame(raw.data(), static_cast<uint32_t>(raw.size()));
            CHECK_NE(result.pdu, nullptr);
        }
    }
}