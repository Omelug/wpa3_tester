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

        PacketWriter writer("probe_res_result.pcap", Tins::DataLinkType<RadioTap>());
        RawPDU raw_pdu(probe_data);
        writer.write(raw_pdu);

        // Verify that the data was modified
        REQUIRE((probe_data != original_data));
        //RadioTap rt(probe_data.data(), probe_data.size());
        //REQUIRE((probe_data.size() == original_data.size()));
        //CHECK((rt.channel_freq() == 2460));

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


}
