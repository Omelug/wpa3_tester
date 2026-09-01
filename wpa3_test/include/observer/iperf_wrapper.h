#pragma once
#include <filesystem>
#include <optional>
#include <vector>
#include "config/RunStatus.h"
#include "logger/log.h"
#include "overview/described.h"

namespace wpa3_tester::observer{
struct IperfData{
	std::vector<double> intervals;
	std::vector<double> bandwidths;
};

void iperf3_graph(const std::filesystem::path &log_path, const std::string &actor_tag, const std::string &output_png);

void start_iperf3(RunStatus &rs, const std::string &actor_name, const std::string &src_name, const std::string &dst_name
);

void start_iperf3_server(RunStatus &rs, const std::string &actor_name, const std::string &server_name);
described_bool iperf_was_down(RunStatus &rs, const std::filesystem::path &test_folder);
}