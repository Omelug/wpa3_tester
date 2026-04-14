#pragma once
#include <vector>

namespace wpa3_tester::test_helpers{
    // read one packet from file (fuck off pcap header and footer)
    std::vector<uint8_t> read_pcap_file(const std::string& filename);
}