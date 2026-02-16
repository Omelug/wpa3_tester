#pragma once
#include "config/RunStatus.h"

namespace wpa3_tester::observer{
    void start_thark(RunStatus &run_status, const std::string &node_name);
    std::string plot_traffic_graph(const RunStatus& rs,
            const std::string& actor_name,
            std::vector<double> times,const std::vector<double>& sizes,
            std::vector<double> highlight_times
            );
    std::string extract_pcap_to_csv(const RunStatus& rs, const std::string& actor_name);

    std::string tshark_graph(const RunStatus &rs,
            const std::string &actor_name,
            const std::vector<double> &highlight_times,
            const std::string& legend_desc);
}
