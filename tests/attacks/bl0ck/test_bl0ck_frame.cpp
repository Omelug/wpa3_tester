#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <filesystem>
#include <tins/tins.h>
#include "attacks/DoS_soft/bl0ck/bl0ck.h"
#include "logger/log.h"

using namespace std;
using namespace Tins;
using namespace filesystem;

namespace wpa3_tester {
    TEST_CASE("send_bl0ck_frame - creates and saves BAR frames to pcap") {
        // Setup test parameters
        const string test_iface = "lo";  // Use loopback for testing
        const HWAddress<6> ap_mac("00:11:22:33:44:55");
        const HWAddress<6> sta_mac("AA:BB:CC:DD:EE:FF");
        constexpr int subtype = 8;  // BAR

        // Create output directory
        const path output_dir = temp_directory_path() / "bl0ck_test";
        create_directories(output_dir);

        const path pcap_file = output_dir / "bar_frames.pcap";


        { //bypass not buffering
            PacketWriter writer(pcap_file.string(), DataLinkType<RadioTap>());
            RadioTap bl0ck_frame = bl0ck_attack::get_BAR_frame(ap_mac, sta_mac);
            writer.write(bl0ck_frame);
        }

        FileSniffer sniffer(pcap_file.string());
        for (auto& pkt : sniffer) {

            // Verify packet structure
            const RadioTap* radiotap = pkt.pdu()->find_pdu<RadioTap>();
            REQUIRE((radiotap != nullptr));

            const Dot11* dot11 = radiotap->find_pdu<Dot11>();
            REQUIRE((dot11 != nullptr));

            CHECK((dot11->type() == Dot11::CONTROL));
            CHECK((dot11->subtype() == subtype));
            CHECK((dot11->addr1() == ap_mac));

            //TODO other checks
        }
        log(LogLevel::INFO, ("PCAP file preserved for inspection:" + pcap_file.string()).c_str());
    }
}

