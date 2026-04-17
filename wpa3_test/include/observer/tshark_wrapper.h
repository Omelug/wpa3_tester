#pragma once
#include "config/RunStatus.h"
#include "grapth/graph_elements.h"
#include "logger/log.h"

namespace wpa3_tester::observer::tshark{

    void start_tshark(RunStatus &rs, const std::string &node_name, const std::string& filter = "udp port 5201");
    std::filesystem::path extract_pcap_to_csv(const std::string& actor_name, const std::filesystem::path& real_folder);
    std::vector<LogTimePoint> get_tshark_events(const RunStatus& rs, const std::string& process_name, const std::string& tshark_filter, const std::string& event_name);
    std::string tshark_graph(const RunStatus &rs,
            const std::string& actor_name,
            const std::vector<std::unique_ptr<GraphElements>>& element = {},
            const std::filesystem::path& folder = "");
    void generate_time_series_retry_graph(const RunStatus &rs,
                    const std::string &actor_name,
                    const std::filesystem::path &folder = "");
    void pcap_events(
        const RunStatus& rs,
        G_el elements,
        // { actor, filter, label, color }
        std::initializer_list<std::tuple<std::string, std::string, std::string, std::string>> event_def);
}
