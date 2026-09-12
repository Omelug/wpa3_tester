#pragma once
#include "config/RunStatus.h"
#include "graph/graph_elements.h"
#include "logger/log.h"
#include "overview/described.h"
#include <optional>

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
											const std::string &tshark_filter, const std::string &event_name,
											std::optional<TimeWindow> window = std::nullopt
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

// --------- SPECIFIC HELPERS -----------
// extract the negotiated AKM from a pcap file (reads wlan.rsn.akms.type via tshark)
// returns e.g. "00-0F-AC:8(WPA3)", "00-0F-AC:2(WPA2)", empty string if not found
std::string akm_from_pcap(const std::filesystem::path &pcap_path);
// extract OCV (OCVC bit of RSNXE) from client frames (Probe Req / Assoc Req) in pcap

// returns true if a frame is found, nullopt if no relevant frame exists
std::optional<bool> client_ocv_from_pcap(const std::filesystem::path &pcap_path);
// extract OCV (OCVC bit of RSNXE) from AP frames (Beacon / Probe Resp)
std::optional<bool> ap_ocv_from_pcap(const std::filesystem::path &pcap_path);

// detect client scanning via Probe Requests in pcap_path within [start_time, end_time]
// return "ch: X Y" (unique channels from wlan.ds.current_channel / radiotap),
// return "yes" if probe requests found but no channel info
// return empty string if no scanning detected
std::string client_scanning_from_pcap(const std::filesystem::path &pcap_path,
									   const std::string &client_mac,
									   TimeWindow window = {});

// detect ADDBA Request/Response (Block Ack action cat=3, action=0/1) in pcap
// returns true if seen, false if pcap exists but none found, nullopt if pcap missing
std::optional<bool> addba_seen_from_pcap(const std::filesystem::path &pcap_path);

// PBAC (Protected Block Ack Agreement Capable, RSN caps bit 12) from AP Beacon / Probe Response.
// Optionally pass run_folder + actor_name to also read saved OpenWrt UCI config (ieee80211w).
described_bool pbac_from_pcap_ap(const std::filesystem::path &pcap_path,
								 const std::string &ap_mac = {});
// PBAC from client Probe Request or Association Request frames
described_bool pbac_from_pcap_client(const std::filesystem::path &pcap_path, const std::string &client_mac = {});
}