#pragma once
#include "config/RunStatus.h"
#include "logger/log.h"
#include "observer/graph/graph_elements.h"
#include "overview/described.h"
#include <filesystem>
#include <optional>
#include <vector>

namespace wpa3_tester::observer{
struct IperfData{
	std::vector<double> intervals;
	std::vector<double> bandwidths;
};

void iperf3_graph(const std::filesystem::path &log_path, const std::string &actor_tag, const std::string &output_png);

void start_iperf3(RunStatus &rs, const std::string &actor_name, const std::string &src_name, const std::string &dst_name
);

void start_iperf3_server(RunStatus &rs, const std::string &actor_name, const std::string &server_name);
described_str iperf_was_down(RunStatus &rs, const std::filesystem::path &test_folder);

// Returns "down" if >=5 consecutive zero-byte intervals, "unstable" if any zeros, empty if clean.
// Threshold constant ZERO_STREAK_THRESHOLD = 5 (intervals = seconds in normal iperf3 output).
described_str iperf_log_has_zero_plain(const std::filesystem::path &log_path, const TimeWindow &window = {});

// parse an iperf3 log file
// return a GraphXYPoints on Y2 axis (0–15 Mbits/sec)
// returns nullopt if the file is missing/contains no parseable intervals
std::optional<GraphXYPoints> iperf_log_to_xy(const std::filesystem::path &log_path,
                                              const std::string &label,
                                              const std::string &color = "blue");
}