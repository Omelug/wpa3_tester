#pragma once
#include "config/RunStatus.h"
#include "graph/graph_elements.h"
#include "logger/log.h"

namespace wpa3_tester::observer::tshark{
std::string or_filter(const std::vector<std::string> &mac_filters);
std::string masked_mac_filter_5(const RunStatus &rs);
std::string all_actors_mac_filter(const RunStatus &rs, bool broadcast = false);
std::pair<std::vector<LogTimePoint>, std::vector<double>> times_packet_sizes_from_csv(const std::filesystem::path &csv_path);
LogTimePoint get_pcap_start_time(const std::string &pcap_path);

void start_tshark_remote(RunStatus &rs, const std::string &actor_name, const std::string &filter);
void start_tshark(RunStatus &rs, const std::string &node_name, const std::string &filter = "udp port 5201");
std::filesystem::path extract_pcap_to_csv(const std::string &actor_name, const std::filesystem::path &real_folder);
std::vector<LogTimePoint> get_tshark_events(const RunStatus &rs, const std::string &process_name,
											const std::string &tshark_filter, const std::string &event_name
);
std::filesystem::path tshark_graph(const RunStatus &rs, const std::string &actor_name,
									const G_elms &elements = {},
									const std::filesystem::path &folder = ""
);
void generate_time_series_retry_graph(const RunStatus &rs, const std::string &actor_name,
									const std::filesystem::path &folder = ""
);
void pcap_events(const RunStatus &rs, G_elms &elements,
				// { actor, filter, label, color }
				std::initializer_list<std::tuple<std::string,std::string,std::string,std::string>> event_def
);
}