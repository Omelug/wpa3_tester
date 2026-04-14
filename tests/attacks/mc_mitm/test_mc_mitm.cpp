#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <vector>
#include "attacks/mc_mitm/mc_mitm.h"
#include "pcap_helper.h"

using namespace std;
using namespace Tins;
using namespace wpa3_tester;

namespace wpa3_tester {
    // TODO change to FCS a
    TEST_CASE("patch_channel_raw - beacon frame") {
        // Test with beacon_test.pcapng
        vector<uint8_t> beacon_data = test_helpers::read_pcap_file("beacon_test.pcapng");
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

    TEST_CASE("patch_channel_raw - probe response frame") {
        // Test with probe_res.pcapng
        vector<uint8_t> probe_data = test_helpers::read_pcap_file("probe_res.pcapng");
        vector<uint8_t> original_data = probe_data; // Keep copy for comparison
        McMitm::patch_channel_raw(probe_data, 11);

        RadioTap rt(probe_data.data(), probe_data.size());
        const Dot11ManagementFrame &mgmt = rt.rfind_pdu<Dot11ManagementFrame>();

        // --- DS Parameter Set (ID=3) ---
        {
            const auto ds_opt = mgmt.search_option(Dot11ManagementFrame::DS_SET);
            CHECK_NE(ds_opt, nullptr);
            CHECK_EQ(ds_opt->data_size(), 1);
            REQUIRE_EQ(ds_opt->data_ptr()[0], 11);
        }

        // --- HT Operation (ID=61) ---
        {
            const auto ht_opt = mgmt.search_option(Dot11ManagementFrame::HT_OPERATION);
            CHECK_NE(ht_opt, nullptr);
            CHECK_GE(ht_opt->data_size(), 1);
            REQUIRE_EQ(ht_opt->data_ptr()[0], 11);
        }

        PacketWriter writer("probe_res_result.pcap", Tins::DataLinkType<RadioTap>());
        RawPDU raw_pdu(probe_data);
        writer.write(raw_pdu);

        // Verify that the data was modified
        REQUIRE_NE(probe_data, original_data);

        INFO("Probe response frame size before: " << original_data.size());
        INFO("Probe response frame size after: " << probe_data.size());
    }

    TEST_CASE("patch_channel_raw - edge cases") {
        // empty data
        vector<uint8_t> empty_data;
        McMitm::patch_channel_raw(empty_data, 6);
        REQUIRE(empty_data.empty());
        
        // too small data
        vector<uint8_t> small_data = {0x00, 0x01, 0x02};
        vector<uint8_t> original_small = small_data;
        McMitm::patch_channel_raw(small_data, 6);
        CHECK_EQ(small_data, original_small); // Should remain unchanged
    }

    TEST_CASE("beacon_to_probe_resp") {
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

}
