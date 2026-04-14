#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>

#include "attacks/DoS_soft/bl0ck/bl0ck.h"
#include "logger/log.h"

using namespace std;
using namespace Tins;
using namespace filesystem;

namespace wpa3_tester {
    TEST_CASE("send_bl0ck_frame - creates and saves BAR frames to pcap") {
        const HWAddress<6> ap_mac("00:11:22:33:44:55");
        const HWAddress<6> sta_mac("AA:BB:CC:DD:EE:FF");

        const path output_dir = temp_directory_path() / "bl0ck_test";
        create_directories(output_dir);

        const path pcap_file = output_dir / "bar_frames.pcap";


        RadioTap bl0ck_frame = bl0ck_attack::get_BAR_frame(ap_mac, sta_mac);

        const RadioTap* radiotap = bl0ck_frame.find_pdu<RadioTap>();
        REQUIRE_NE(radiotap, nullptr);

        const auto* dot11 = radiotap->find_pdu<Dot11>();
        REQUIRE_NE(dot11, nullptr);

        CHECK_EQ(dot11->type(), Dot11::CONTROL);
        CHECK_EQ(dot11->subtype(), 8);
        CHECK_EQ(dot11->addr1(), sta_mac);

        log(LogLevel::INFO, ("PCAP file preserved for inspection:"+pcap_file.string()).c_str());
    }
}

