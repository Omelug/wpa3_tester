#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include "pcap_helper.h"
#include "attacks/mc_mitm/MonitorSocket.h"

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

// ─── Sequence test: multiple frames from a single pcap file ──────────────────

TEST_SUITE("MonitorSocket::parse_frame sequence") {

    TEST_CASE("all frames in multi-frame pcap parse without error") {
        const auto frames = test_helpers::read_all_frames(PCAP_MULTI);
        REQUIRE_UNARY_FALSE(frames.empty());

        for (const auto &raw : frames) {
            auto result = MonitorSocket::parse_frame(raw.data(),
                                                     static_cast<uint32_t>(raw.size()));
            CHECK_NE(result.pdu, nullptr);
        }
    }
}