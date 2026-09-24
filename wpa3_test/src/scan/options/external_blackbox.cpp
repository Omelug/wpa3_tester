#include "attacks/components/sniffer_helper.h"
#include "config/Actor_Config/Actor_Config_external.h"
#include "config/Actor_Config/Actor_Config_internal.h"
#include "config/RunStatus.h"
#include "config/global_config.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "scan/active/scan_STA.h"
#include "system/hw_capabilities.h"
#include <pcap/pcap.h>
#include <set>

namespace wpa3_tester{
using namespace std;
using namespace Tins;

#define INVALID_VALUE (0)

//TODO integration tests?

void RunStatus::solve_new_pdu(PDU &pdu, ActorMACMap &seen, AssocMap &assoc){
	int8_t signal = INVALID_VALUE;
	uint16_t freq = INVALID_VALUE;
	if(const auto *rt = pdu.find_pdu<RadioTap>()){
		try{ signal = rt->dbm_signal(); } catch(...){} // not avaible TODO check fsc forst? ?
		try{ freq = rt->channel_freq(); } catch(...){} //TODO not
	}

	const auto add_conn = [&](const HWAddress<6> &sta, const HWAddress<6> &ap, const string &reason){
		if(assoc.contains(sta)) return;
		log(LogLevel::DEBUG, "Connection: {} -> AP {} ({})", sta, ap, reason);
		assoc[sta] = ap;
	};

	const auto add_entity = [&](const HWAddress<6> &mac, const bool is_ap, const string &ssid = ""){
		if(mac.is_multicast() || mac.is_broadcast()) return;
		ActorPtr actor;
		const bool is_new = !seen.contains(mac);
		if(is_new){
			actor = ActorPtr(make_shared<Actor_Config_external>());
			seen.emplace(mac, actor);
		} else{
			actor = seen.at(mac);
		}
		actor->set(SK::mac, mac);
		actor->set(SK::permanent_mac, mac);
		if(is_new) log(LogLevel::INFO, "New external actor: {}", actor->to_str());
		if(!ssid.empty()) actor->set(SK::ssid, ssid);
		if(!actor[BK::AP].has_value())  actor->set(BK::AP,  is_ap);
		if(!actor[BK::STA].has_value()) actor->set(BK::STA, !is_ap);
		if(freq != INVALID_VALUE){
			//TODO frequency ranges ser multiple times
			if(freq >= 2412 && freq <= 2484)        actor->set(BK::GHz2_4, true);
			else if(freq >= 5170 && freq <= 5885)   actor->set(BK::GHz5,   true);
			else if(freq >= 5945 && freq <= 7125)   actor->set(BK::GHz6,   true);
			actor->set(SK::channel, to_string(hw_capabilities::freq_to_channel(freq)));
		}
		if(signal != INVALID_VALUE) actor->set(SK::signal, to_string(signal));
	};

	if(const auto *beacon = pdu.find_pdu<Dot11Beacon>()){
		string ssid;
		try{ ssid = beacon->ssid(); } catch(...){}
		add_entity(beacon->addr2(), true, ssid);
	} else if (const auto *probe_resp = pdu.find_pdu<Dot11ProbeResponse>()) {
		string ssid;
		try{ ssid = probe_resp->ssid(); } catch(...){}
		add_entity(probe_resp->addr2(), true, ssid);
	} else if(const auto *probe_req = pdu.find_pdu<Dot11ProbeRequest>()){
		string ssid;
		try{ ssid = probe_req->ssid(); } catch(...){}
		add_entity(probe_req->addr2(), false, ssid);
	} else if (const auto *mgmt = pdu.find_pdu<Dot11ManagementFrame>()) {
		if (mgmt->subtype() == Dot11::ManagementSubtypes::ASSOC_REQ ||
			mgmt->subtype() == Dot11::ManagementSubtypes::REASSOC_REQ) {
			const HWAddress<6> sta_mac = mgmt->addr2();
			if (sta_mac.is_unicast()) {
				if (!seen.contains(sta_mac))
					seen.emplace(
						sta_mac,
						ActorPtr(make_shared<Actor_Config_external>()));
				if (auto *ext = dynamic_cast<Actor_Config_external *>(
						seen.at(sta_mac).get())) {
					scan::fill_actor_caps_from_assoc_req(pdu, *ext);
					ext->set(SK::permanent_mac, sta_mac);
				}
				const HWAddress<6> ap_bssid = mgmt->addr1();
				if (ap_bssid.is_unicast()) {
					add_conn(sta_mac, ap_bssid, mgmt->subtype() == Dot11::ManagementSubtypes::ASSOC_REQ ? "assoc-req" : "reassoc-req");
				}
			}
		}
	} else if (const auto *data = pdu.find_pdu<Dot11Data>()) {
		const bool to_ds = data->to_ds();
		const bool from_ds = data->from_ds();
		if (to_ds && !from_ds) {
			add_entity(data->addr2(), false);
			add_entity(data->addr1(), true);
			if (data->addr2().is_unicast() && data->addr1().is_unicast()) {
				add_conn(data->addr2(), data->addr1(), "data-to-ds");
			}
		} else if (!to_ds && from_ds) {
			add_entity(data->addr1(), false);
			add_entity(data->addr2(), true);
			if (data->addr1().is_unicast() && data->addr2().is_unicast()) {
				add_conn(data->addr1(), data->addr2(), "data-from-ds");
			}
		}
	}
}

void RunStatus::solve_new_pdu(const frame_raw_t &frame, ActorMACMap &seen, AssocMap &assoc){
	RadioTap rt;
	try {
		rt = RadioTap(frame.data(), frame.size());
	} catch(...){ return; } //FIXME ignore  or check it with fskfail
	solve_new_pdu(rt, seen, assoc);
}

static pcap_t *open_scan_pcap(const string &iface, const ActorPtr &scanner){
	scanner->set_monitor_mode();
	scanner->set_iface_up();

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_create(iface.c_str(), errbuf);
	if(!handle) throw setup_err("pcap_create failed: " + string(errbuf));
	pcap_set_snaplen(handle, 2000);
	pcap_set_promisc(handle, 1);
	pcap_set_timeout(handle, 100);
	if(pcap_activate(handle) < 0){
		const string msg = pcap_geterr(handle);
		pcap_close(handle);
		throw setup_err("pcap_activate failed: {}",  msg);
	}
	return handle;
}

vector<EntityInfo> RunStatus::list_external_entities(const string &iface, const size_t timeout_sec,
													const vector<uint8_t> &channels
){
	if(channels.empty()) throw setup_err("No channels specified for scanning");

	const ActorPtr scanner(make_shared<Actor_Config_internal>());
	scanner->set(SK::iface, iface);
	pcap_t *handle = open_scan_pcap(iface, scanner);
	struct PcapGuard{
		pcap_t *h;
		~PcapGuard(){ pcap_close(h); }
	} _guard{handle};

	ActorMACMap seen;
	AssocMap assoc;
	constexpr size_t SEC_MINIMUM = 2;
	const size_t channel_sec = max<size_t>(SEC_MINIMUM, timeout_sec / channels.size());
	const auto total_end = chrono::steady_clock::now() + chrono::seconds(timeout_sec);

	for(const uint8_t channel: channels){
		if(chrono::steady_clock::now() >= total_end || g_interrupted) break;
		log(LogLevel::INFO, "Scanning channel {} on {}", channel, iface);

		const Channel ch{channel, WifiBand::BAND_2_4_or_5, nullopt}; //FIXME only 2_4/5Ghz
		scanner->set_channel(ch);
		interruptible_sleep(chrono::milliseconds(200)); //TODO needed -test?

		const auto result = components::poll_sniffer<monostate>(handle, chrono::seconds(channel_sec),
											[&](const frame_raw_t &frame) ->optional<monostate>{
												try {
													solve_new_pdu(frame, seen, assoc);
												} catch(...){}//TODO needed?
												return nullopt;
											});
		if(holds_alternative<StopReason>(result) && get<StopReason>(result) == StopReason::Interrupted) break;
	}

	vector<EntityInfo> result;
	result.reserve(seen.size());
	for(const auto &[mac, actor]: seen){
		const HWAddress<6> peer = assoc.contains(mac) ? assoc.at(mac) : HWAddress<6>{};
		result.emplace_back(actor, make_pair(mac, peer));
	}
	return result;
}

vector<uint8_t> RunStatus::get_external_bb_channels(){
	vector<uint8_t> all_channels;

	if(_config.contains("scan_channels")){
		all_channels = _config.at("scan_channels").get<vector<uint8_t>>();
	} else{
		for(const auto &[actor_name, actor_config]: _config.at("actors").items()){
			if(actor_config.value("scan_ignore", false)) continue;
			if(!actor_config.contains("selection")) continue;
			if(actor_config.at("selection").contains("channel")){
				all_channels.push_back(actor_config.at("selection").at("channel").get<uint8_t>());
			} else{
				log(LogLevel::WARNING, "Actor {} missing channel configuration", actor_name);
			}
		}
		all_channels = ranges::to<std::vector>(set(all_channels.begin(), all_channels.end()));
	}

	if(all_channels.empty()){
		log(LogLevel::WARNING, "No channels found for scanning");
		return {};
	}

	const auto s = all_channels | views::transform([](const uint8_t c){ return to_string(c); }) |
			views::join_with(string(", ")) | ranges::to<string>();
	log(LogLevel::INFO, "Scanning channels: {}", s);
	return all_channels;
}

vector<ActorPtr> RunStatus::external_bb_options(
	const ActorMap &ex_bb_actors, const std::vector<std::string> &disabled_tests_hash_filler
	){
	const vector<uint8_t> channels = get_external_bb_channels();
	if(channels.empty()) return {};
	const string iface = _config.at("scan_iface");
	const int timeout = get_global_config().at("timeout_external_bb_scan_sec").get<int>();

	vector<pair<string,string>> conn_conds;
	if(_config.contains("requirements") && _config.at("requirements").contains("ex_BB_connection")){
		for(const auto &p : _config.at("requirements").at("ex_BB_connection"))
			conn_conds.emplace_back(p[0].get<string>(), p[1].get<string>());
	}

	if(_config.value("scan_until_match", false) && !ex_bb_actors.empty())
		return scan_until_match(iface, channels, ex_bb_actors, conn_conds, disabled_tests_hash_filler);

	const auto entities = list_external_entities(iface, timeout, channels);
	return entities | views::transform([](const EntityInfo &e){ return e.first; }) | ranges::to<vector<ActorPtr>>();
}

bool RunStatus::process_single_pdu(
	const frame_raw_t &frame,
	ActorMACMap &seen, AssocMap &assoc, set<HWAddress<6>> &reported,
	const ActorMap &actors, const vector<pair<string,string>> &conn_conds,
	std::vector<std::string> disabled_tests_hash_filler
) {
	const size_t before_seen = seen.size();
	const size_t before_assoc = assoc.size();
	try {
		solve_new_pdu(frame, seen, assoc);
	} catch(...) {} //FIXME needed? - testwith fail FSC

	if (seen.size() > before_seen) {
		for (const auto &[mac, actor] : seen) {
			if (!reported.insert(mac).second) continue;
			const bool is_ap = actor->get_or(BK::AP, false);
			log(LogLevel::INFO, "  + {} {} ssid='{}' ch={} signal={}dBm", is_ap ? "AP " : "STA", mac,
				actor->get_or(SK::ssid, ""), actor->get_or(SK::channel, "?"), actor->get_or(SK::signal, "?"));
		}
	}

	if (seen.size() > before_seen || assoc.size() > before_assoc) {
		const auto opts = seen | views::values | ranges::to<vector<ActorPtr>>();
		try {
			const ActorMap assignment = check_req_options(actors, opts, false, disabled_tests_hash_filler);
			for (const auto &[ap_name, sta_name] : conn_conds) {
				// both (STA and AP) have to be scanned
				if (!assignment.contains(sta_name) || !assignment.contains(ap_name)) return false;

				const HWAddress<6> sta_mac(assignment.at(sta_name)->get(SK::mac));
				const HWAddress<6> ap_mac(assignment.at(ap_name)->get(SK::mac));

				// STA not connected or not connected to AP
				if (!assoc.contains(sta_mac) || assoc.at(sta_mac) != ap_mac)  return false;
			}
			return true; // all condition passed
		} catch (const req_err &) {} // ignore invalid requires
	}
	return false;
}

vector<ActorPtr> RunStatus::scan_until_match(const string &iface, const vector<uint8_t> &channels,
											  const ActorMap &actors,
											  const vector<pair<string,string>> &conn_conds,
											  std::vector<std::string> disabled_tests_hash_filler

){
	const ActorPtr scanner(make_shared<Actor_Config_internal>());
	scanner->set(SK::iface, iface);
	scanner->set_monitor_mode();
	pcap_t *handle = open_scan_pcap(iface, scanner);
	struct PcapGuard{
		pcap_t *h;
		~PcapGuard(){ pcap_close(h); }
	} _guard{handle};

	ActorMACMap seen;
	AssocMap assoc;
	set<HWAddress<6>> reported;
	const auto on_frame = [&](const frame_raw_t &frame) -> optional<bool> {
		return process_single_pdu(frame, seen, assoc, reported, actors, conn_conds, disabled_tests_hash_filler) ? optional{true} : nullopt;
	};

	for(const uint8_t ch_num: channels){
		// at the end of filler there will be one error test file
		if(g_interrupted) throw interrupted_err("scan_until_match loop"); //TODO needed?

		log(LogLevel::INFO, "Scanning channel {} on {}", ch_num, iface);
		scanner->set_channel(Channel{ch_num, WifiBand::BAND_2_4, nullopt});

		//FIXME needed , should be in set_channel?
		interruptible_sleep(chrono::milliseconds(200)); //TODO hardcoded timers
		const auto result = components::poll_sniffer<bool>(handle, chrono::seconds(2), on_frame); //FIXME hardcoded time
		if(!holds_alternative<StopReason>(result)) break;  // found
		if(get<StopReason>(result) == StopReason::Interrupted) break; //TODO INterruped je tu asi zbytečné, kdyžtak jen chytnout error?
	}
	return seen | views::values | ranges::to<vector<ActorPtr>>();
}
}