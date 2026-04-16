#pragma once
#include <string>

#include "tshark_wrapper.h"
#include "config/RunStatus.h"

namespace wpa3_tester::observer::resource_checker{
    const std::string SUFFIX_res = "_res";
    struct ResourceRecord {
        long long timestamp;
        std::vector<int> core_percents;
        long long mem_free_kb;
        int airtime_pct;
        int rx_drops;
    };
    void start_resource_monitoring_remote(RunStatus &rs,
        const std::string &actor_name, const std::string &iface, int interval_sec);
    void start_resource_monitoring(RunStatus &rs, const std::string &actor_name, int interval_sec);
    void generate_resource_graph(const std::string& data_filepath,
                         const std::string& output_imagepath,
                         const std::vector<std::unique_ptr<GraphElements>>& elements = {});
    void create_resource_monitor_graph(const std::string& data_filepath);
    void create_resource_pid_graph(const std::string& data_filepath);
    void create_graph(const RunStatus &rs, const std::string &source);
}
