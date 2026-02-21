#pragma once
#include "config/RunStatus.h"
#include "logger/log.h"

namespace wpa3_tester::observer{

    struct graph_lines{
        std::vector<LogTimePoint> highlight_times;
        std::string event_des;
        std::string color = "blue";
    };

    void start_thark(RunStatus &run_status, const std::string &node_name);
    std::string plot_traffic_graph(const RunStatus& rs,
            const std::string& actor_name,
            const std::vector<LogTimePoint>& times, const std::vector<double>& sizes,
            const std::vector<graph_lines>& event);
    std::filesystem::path extract_pcap_to_csv(const RunStatus& rs, const std::string& actor_name);

    std::string tshark_graph(const RunStatus &rs,
            const std::string& actor_name,
            const std::vector<graph_lines>& events);
}
