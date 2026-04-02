#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <tins/tins.h>
#include <fstream>
#include <vector>
#include "attacks/mc_mitm/mc_mitm.h"

using namespace std;
using namespace Tins;
using namespace wpa3_tester;

namespace wpa3_tester {

    static vector<uint8_t> read_pcap_file(const string& filename) {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_offline(filename.c_str(), errbuf);

        pcap_pkthdr* header;
        const u_char* packet;

        pcap_next_ex(handle, &header, &packet);
        std::vector frame_data(packet, packet + header->caplen);
        pcap_close(handle);

        return frame_data;
    }

    // TODO change to FCS a
    TEST_CASE("patch_channel_raw - beacon frame") {
        // Test with beacon_test.pcapng
        vector<uint8_t> beacon_data = read_pcap_file("beacon_test.pcapng");
        vector<uint8_t> original_data = beacon_data; // Keep copy for comparison
        
        // Patch to channel 6
        constexpr uint8_t target_channel = 6;
        McMitm::patch_channel_raw(beacon_data, target_channel);


        PacketWriter writer("beacon_patched_result.pcap", Tins::DataLinkType<RadioTap>());
        RawPDU raw_pdu(beacon_data);
        writer.write(raw_pdu);

        // Verify that the data was modified
        REQUIRE((beacon_data != original_data));
        REQUIRE((beacon_data.size() != original_data.size()));


        INFO("Beacon frame size before: " << original_data.size());
        INFO("Beacon frame size after: " << beacon_data.size());
    }

    TEST_CASE("patch_channel_raw - probe response frame") {
        // Test with probe_res.pcapng
        vector<uint8_t> probe_data = read_pcap_file("probe_res.pcapng");
        vector<uint8_t> original_data = probe_data; // Keep copy for comparison
        McMitm::patch_channel_raw(probe_data, 11);

        RadioTap rt(probe_data.data(), probe_data.size());
        const Dot11ManagementFrame &mgmt = rt.rfind_pdu<Dot11ManagementFrame>();

        // --- DS Parameter Set (ID=3) ---
        {
            const auto ds_opt = mgmt.search_option(Dot11ManagementFrame::DS_SET);
            REQUIRE((ds_opt != nullptr));
            REQUIRE((ds_opt->data_size() == 1));
            REQUIRE((ds_opt->data_ptr()[0] == 11));
        }

        // --- HT Operation (ID=61) ---
        {
            const auto ht_opt = mgmt.search_option(Dot11ManagementFrame::HT_OPERATION);
            REQUIRE((ht_opt != nullptr));
            REQUIRE((ht_opt->data_size() >= 1));
            REQUIRE((ht_opt->data_ptr()[0] == 11));
        }

        PacketWriter writer("probe_res_result.pcap", Tins::DataLinkType<RadioTap>());
        RawPDU raw_pdu(probe_data);
        writer.write(raw_pdu);

        // Verify that the data was modified
        REQUIRE((probe_data != original_data));

        INFO("Probe response frame size before: " << original_data.size());
        INFO("Probe response frame size after: " << probe_data.size());
    }

    TEST_CASE("patch_channel_raw - edge cases") {
        // Test with empty data
        vector<uint8_t> empty_data;
        McMitm::patch_channel_raw(empty_data, 6);
        REQUIRE(empty_data.empty());
        
        // Test with too small data
        vector<uint8_t> small_data = {0x00, 0x01, 0x02};
        vector<uint8_t> original_small = small_data;
        McMitm::patch_channel_raw(small_data, 6);
        REQUIRE((small_data == original_small)); // Should remain unchanged
    }

    TEST_CASE("beacon_to_probe_resp") {
        Dot11Beacon beacon;
        beacon.addr2("aa:bb:cc:dd:ee:ff");
        beacon.addr3("aa:bb:cc:dd:ee:ff");
        beacon.interval(100);
        beacon.ds_parameter_set(6);
        beacon.ssid("TestNet");

        unique_ptr<Dot11ProbeResponse> probe(beacon_to_probe_resp(beacon, 11));

        REQUIRE((probe->addr2() == beacon.addr2()));
        REQUIRE((probe->addr3() == beacon.addr3()));
        REQUIRE((probe->interval() == beacon.interval()));
        REQUIRE((probe->ds_parameter_set() == 11));
        REQUIRE((probe->search_option(Dot11::SSID) != nullptr));
        REQUIRE((probe->search_option(Dot11::TIM) == nullptr));
    }

}
