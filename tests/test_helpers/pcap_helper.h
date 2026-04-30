#pragma once
#include <vector>

namespace wpa3_tester::test_helpers{
std::pair<Tins::RadioTap,std::vector<uint8_t>> load_frame(const char *path);
std::vector<std::vector<uint8_t>> read_all_frames(const std::string &path);
std::pair<pcap_pkthdr,std::vector<uint8_t>> read_one_frame(const std::string &path);
// read one packet from file (fuck off pcap header and footer)
std::vector<uint8_t> read_pcap_file(const std::string &filename);
}