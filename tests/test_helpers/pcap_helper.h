#pragma once
#include <vector>

#include "config/RunStatus.h"

namespace wpa3_tester::test_helpers {
std::pair<Tins::RadioTap, frame_raw_t> load_frame(const char *path);
std::vector<frame_raw_t> read_all_frames(const std::string &path);
frame_raw_t read_one_frame(const std::string &path);
// read one PDU from file (fuck off pcap header and footer)
frame_raw_t read_pcap_file(const std::string &filename);
}