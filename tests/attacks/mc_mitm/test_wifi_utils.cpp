#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <vector>
#include "pcap_helper.h"
#include "attacks/mc_mitm/mc_mitm.h"

using namespace std;
using namespace Tins;
using namespace wpa3_tester;

namespace wpa3_tester{

TEST_CASE("patch_channel_raw - beacon frame"){
    vector<uint8_t> beacon_data = test_helpers::read_pcap_file("./pcap/.pcapng");
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

}