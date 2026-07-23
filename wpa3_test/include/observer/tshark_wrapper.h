#pragma once
#include "config/RunStatus.h"
#include "graph/graph_elements.h"
#include "logger/log.h"

namespace wpa3_tester::observer::tshark{
std::string or_filter(const std::vector<std::string> &mac_filters);
std::string masked_mac_filter_5(const RunStatus &rs);
std::string all_actors_mac_filter(const RunStatus &rs, bool broadcast = false);
std::pair<std::vector<LogTimePoint>,std::vector<double>> times_packet_sizes_from_csv(
	const std::filesystem::path &csv_path
);
LogTimePoint get_pcap_start_time(const std::string &pcap_path);

void start_tshark_remote(RunStatus &rs, const std::string &actor_name, const std::string &filter);
void start_tshark(RunStatus &rs, const std::string &node_name, const std::string &filter = "udp port 5201");
std::filesystem::path extract_pcap_to_csv(const std::string &actor_name, const std::filesystem::path &real_folder,
										const std::string &tshark_filter = "");
std::vector<LogTimePoint> get_tshark_events(const RunStatus &rs, const std::string &process_name,
											const std::string &tshark_filter, const std::string &event_name
);
std::filesystem::path tshark_graph(const RunStatus &rs, const std::string &actor_name, const G_elms &elements = {},
									const std::filesystem::path &folder = "",
									const std::string &tshark_filter = ""
);
void generate_time_series_retry_graph(const RunStatus &rs, const std::string &actor_name,
									const std::filesystem::path &folder = ""
);
void pcap_events(const RunStatus &rs, G_elms &elements,
				// { actor, filter, label, color }
				std::initializer_list<std::tuple<std::string,std::string,std::string,std::string>> event_def
);

// Extract the negotiated AKM from a pcap file (reads wlan.rsn.akms.type via tshark).
// Returns e.g. "00-0F-AC:8(WPA3)", "00-0F-AC:2(WPA2)", or empty string if not found.
std::string akm_from_pcap(const std::filesystem::path &pcap_path);
// Extract OCV (OCVC bit of RSNXE) from client frames (Probe Req / Assoc Req).
// Returns true/false if a frame is found, nullopt if no relevant frame exists in the pcap.
std::optional<bool> client_ocv_from_pcap(const std::filesystem::path &pcap_path);
// Extract OCV (OCVC bit of RSNXE) from AP frames (Beacon / Probe Resp).
std::optional<bool> ap_ocv_from_pcap(const std::filesystem::path &pcap_path);
// Detect client scanning via Probe Requests in pcap_path within [start_time, end_time].
// Returns "ch: X Y" (unique channels from wlan.ds.current_channel / radiotap), "yes" if
// probe requests found but no channel info, or empty string if no scanning detected.
std::string client_scanning_from_pcap(const std::filesystem::path &pcap_path,
                                       const std::string &client_mac,
                                       LogTimePoint start_time, LogTimePoint end_time);
}