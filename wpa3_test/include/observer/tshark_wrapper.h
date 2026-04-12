#pragma once
#include "config/RunStatus.h"
#include "logger/log.h"

namespace wpa3_tester::observer{

    struct graph_lines{
        std::vector<LogTimePoint> highlight_times;
        std::string event_des;
        std::string color = "blue";
    };

    void start_tshark(RunStatus &rs, const std::string &node_name, const std::string& filter = "udp port 5201");
    std::string plot_traffic_graph(const RunStatus& rs,
            const std::string& actor_name,
            const std::vector<LogTimePoint>& times, const std::vector<double>& sizes,
            const std::vector<graph_lines>& event);
    std::filesystem::path extract_pcap_to_csv(const std::string& actor_name, const std::filesystem::path& real_folder);
    std::vector<LogTimePoint> get_tshark_events(const RunStatus& rs, const std::string& process_name, const std::string& tshark_filter, const std::string& event_name);
    std::string tshark_graph(const RunStatus &rs,
            const std::string& actor_name,
            std::vector<graph_lines>& events,
            const std::filesystem::path& folder = "");
    void generate_time_series_retry_graph(const RunStatus &rs,
                    const std::string &actor_name,
                    const std::filesystem::path &folder = "");
}
