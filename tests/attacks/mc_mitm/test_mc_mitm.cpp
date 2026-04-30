#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <vector>
#include "attacks/mc_mitm/mc_mitm.h"
#include "pcap_helper.h"

using namespace std;
using namespace Tins;
using namespace wpa3_tester;

namespace wpa3_tester{
TEST_CASE("MonitorSocket receives all auth frames from pcap"){
    const string pcap_path = "./pcap/rogue_client_capture.pcap";
    const string ap_mac = "78:98:e8:55:3e:8d";
    const string client_mac = "24:ec:99:bf:c7:cf";

    int expected_ap_to_client = 0;
    int expected_client_to_ap = 0;

    FileSniffer file_sniffer(pcap_path);
    file_sniffer.sniff_loop([&](PDU &pdu) ->bool{
        const auto *mgmt = pdu.find_pdu<Dot11ManagementFrame>();
        if(!mgmt) return true;
        if(!pdu.find_pdu<Dot11Authentication>()) return true;

        if(mgmt->addr2().to_string() == ap_mac && mgmt->addr1().to_string() == client_mac) expected_ap_to_client++;
        else if(mgmt->addr2().to_string() == client_mac && mgmt->addr1().to_string() == ap_mac) expected_client_to_ap++;
        return true;
    });

    REQUIRE_GT(expected_ap_to_client, 0);
    REQUIRE_GT(expected_client_to_ap, 0);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(pcap_path.c_str(), errbuf);
    REQUIRE_NE(handle, nullptr);

    int got_ap_to_client = 0;
    int got_client_to_ap = 0;

    pcap_pkthdr *header;
    const u_char *frame;
    while(pcap_next_ex(handle, &header, &frame) == 1){
        try{
            RadioTap rt(frame, header->caplen);
            const auto *mgmt = rt.find_pdu<Dot11ManagementFrame>();
            if(!mgmt) continue;
            if(!rt.find_pdu<Dot11Authentication>()) continue;

            if(mgmt->addr2().to_string() == ap_mac && mgmt->addr1().to_string() == client_mac) got_ap_to_client++;
            else if(mgmt->addr2().to_string() == client_mac && mgmt->addr1().to_string() == ap_mac) got_client_to_ap++;
        } catch(...){}
    }

    pcap_close(handle);
    CHECK_EQ(got_ap_to_client, expected_ap_to_client);
    CHECK_EQ(got_client_to_ap, expected_client_to_ap);
}

// TODO change to FCS a
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

TEST_CASE("patch_channel_raw - probe response frame"){
    vector<uint8_t> probe_data = test_helpers::read_pcap_file("./pcap/probe_res.pcapng");
    vector<uint8_t> original_data = probe_data;
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

    REQUIRE_NE(probe_data, original_data);

    INFO("Probe response frame size before: " << original_data.size());
    INFO("Probe response frame size after: " << probe_data.size());
}

TEST_CASE("patch_channel_raw - edge cases"){
    // empty data
    vector<uint8_t> empty_data;
    McMitm::patch_channel_raw(empty_data, 6);
    REQUIRE(empty_data.empty());

    // too small data
    vector<uint8_t> small_data = {0x00, 0x01, 0x02};
    vector<uint8_t> original_small = small_data;
    McMitm::patch_channel_raw(small_data, 6);
    CHECK_EQ(small_data, original_small);
}
}
