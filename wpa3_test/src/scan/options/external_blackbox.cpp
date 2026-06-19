#include <pcap/pcap.h>
#include <set>
#include "attacks/components/sniffer_helper.h"
#include "config/global_config.h"
#include "config/RunStatus.h"
#include "config/Actor_Config/Actor_Config_external.h"
#include "config/Actor_Config/Actor_Config_internal.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "scan/active/scan_STA.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester{
using namespace std;
using namespace Tins;

void RunStatus::solve_new_pdu(PDU &pdu, ActorMACMap &seen){
	int8_t signal = -1;
	int channel_freq = -1;
	if(const auto *rt = pdu.find_pdu<RadioTap>()){
		try{ signal = rt->dbm_signal(); } catch(...){}
		try{ channel_freq = rt->channel_freq(); } catch(...){}
	}

	const auto add_entity = [&](const HWAddress<6> &mac, const bool is_ap, const string &ssid = ""){
		if(mac[0] & 0x01) return; // skip broadcast / multicast
		ActorPtr actor;
		if(seen.contains(mac)){
			actor = seen.at(mac);
		} else{
			actor = ActorPtr(make_shared<Actor_Config_external>());
			seen.emplace(mac, actor);
		}
		actor->set(SK::mac, mac);
		actor->set(SK::permanent_mac, mac);

		actor->set(SK::ssid, ssid);
		actor->set(BK::AP, is_ap);
		actor->set(BK::STA, !is_ap);

		if(channel_freq > 0){
			if(channel_freq >= 2412 && channel_freq <= 2484) actor[BK::GHz2_4] = true;
			else if(channel_freq >= 5170 && channel_freq <= 5885) actor[BK::GHz5] = true;
			else if(channel_freq >= 5945 && channel_freq <= 7125) actor[BK::GHz6] = true;
			actor->set(SK::channel, to_string(hw_capabilities::freq_to_channel(channel_freq)));
		}
		if(signal != -1) actor->set(SK::signal, to_string(signal));
	};

	if(const auto *beacon = pdu.find_pdu<Dot11Beacon>()){
		string ssid;
		try{ ssid = beacon->ssid(); } catch(...){}
		add_entity(beacon->addr2(), true, ssid);
	} else if(const auto *probe_resp = pdu.find_pdu<Dot11ProbeResponse>()){
		string ssid;
		try{ ssid = probe_resp->ssid(); } catch(...){}
		add_entity(probe_resp->addr2(), true, ssid);
	} else if(const auto *probe_req = pdu.find_pdu<Dot11ProbeRequest>()){
		string ssid;
		try{ ssid = probe_req->ssid(); } catch(...){}
		add_entity(probe_req->addr2(), false, ssid);
	} else if(const auto *mgmt = pdu.find_pdu<Dot11ManagementFrame>()){
		if(mgmt->subtype() == 0 || mgmt->subtype() == 2){ // assoc-req / reassoc-req
			const HWAddress<6> sta_mac = mgmt->addr2();
			if(!(sta_mac[0] & 0x01)){ // filter multicast/broadcast
				if(!seen.contains(sta_mac)) seen.emplace(sta_mac, ActorPtr(make_shared<Actor_Config_external>()));
				if(auto *ext = dynamic_cast<Actor_Config_external *>(seen.at(sta_mac).get())){
					scan::fill_actor_caps_from_assoc_req(pdu, *ext);
					ext->set(SK::permanent_mac, sta_mac);
				}
			}
		}
	} else if(const auto *data = pdu.find_pdu<Dot11Data>()){
		const bool to_ds = data->to_ds();
		const bool from_ds = data->from_ds();
		if(to_ds && !from_ds){
			add_entity(data->addr2(), false);
			add_entity(data->addr1(), true);
		} else if(!to_ds && from_ds){
			add_entity(data->addr1(), false);
			add_entity(data->addr2(), true);
		}
	}
}

void RunStatus::solve_new_pdu(const vector<uint8_t> &pkt, ActorMACMap &seen){
	RadioTap rt;
	try{ rt = RadioTap(pkt.data(), pkt.size()); } catch(...){ return; }
	solve_new_pdu(rt, seen);
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
		throw setup_err("pcap_activate failed: " + msg);
	}
	return handle;
}

vector<ActorPtr> RunStatus::list_external_entities(const string &iface, const size_t timeout_sec,
													const vector<int> &channels
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
	constexpr size_t SEC_MINIMUM = 2;
	const size_t channel_sec = max<size_t>(SEC_MINIMUM, timeout_sec / channels.size());
	const auto total_end = chrono::steady_clock::now() + chrono::seconds(timeout_sec);

	for(const int channel: channels){
		if(chrono::steady_clock::now() >= total_end) break;
		log(LogLevel::INFO, "Scanning channel {} on {}", channel, iface);

		const Channel ch{channel, WifiBand::BAND_2_4_or_5, nullopt}; //FIXME only 2_4/5Ghz
		scanner->set_channel(ch);
		this_thread::sleep_for(chrono::milliseconds(200));

		components::poll_sniffer<monostate>(handle, chrono::milliseconds(channel_sec * 1000),
											[&](const uint8_t *pkt, const size_t len) ->optional<monostate>{
												try{ solve_new_pdu(vector(pkt, pkt + len), seen); } catch(...){}
												return nullopt;
											});
	}
	return seen | views::values | ranges::to<vector<ActorPtr>>();
}

vector<int> RunStatus::get_external_BB_channels(){
	vector<int> all_channels;

	if(_config.contains("scan_channels")){
		all_channels = _config.at("scan_channels").get<vector<int>>();
	} else{
		for(const auto &[actor_name, actor_config]: _config.at("actors").items()){
			if(actor_config.at("selection").contains("channel")){
				all_channels.push_back(actor_config.at("selection").at("channel").get<int>());
			} else{
				log(LogLevel::WARNING, "Actor {} missing channel configuration", actor_name);
			}
		}
		ranges::sort(all_channels);
		all_channels.erase(ranges::unique(all_channels).begin(), all_channels.end());
	}

	if(all_channels.empty()){
		log(LogLevel::WARNING, "No channels found for scanning");
		return {};
	}

	const auto s = all_channels | views::transform([](const int c){ return to_string(c); }) |
			views::join_with(string(", ")) | ranges::to<string>();
	log(LogLevel::INFO, "Scanning channels: {}", s);
	return all_channels;
}

vector<ActorPtr> RunStatus::scan_until_match(const string &iface, const vector<int> &channels, const ActorCMap &actors){
	const ActorPtr scanner(make_shared<Actor_Config_internal>());
	scanner->set(SK::iface, iface);
	scanner->set_monitor_mode();
	pcap_t *handle = open_scan_pcap(iface, scanner);
	struct PcapGuard{
		pcap_t *h;
		~PcapGuard(){ pcap_close(h); }
	} _guard{handle};

	ActorMACMap seen;
	set<HWAddress<6>> reported;
	bool found = false;

	const auto on_packet = [&](const uint8_t *pkt, const size_t len) ->optional<bool>{
		const size_t before = seen.size();
		try{ solve_new_pdu(vector(pkt, pkt + len), seen); } catch(...){}

		if(seen.size() > before){
			for(const auto &[mac, actor]: seen){
				if(!reported.insert(mac).second) continue;
				const bool is_ap = (*actor)[BK::AP].value_or(false);
				log(LogLevel::INFO, "  + {} {} ssid='{}' ch={} signal={}dBm", is_ap ? "AP " : "STA", mac,
					actor->get_or(SK::ssid, ""), actor->get_or(SK::channel, "?"), actor->get_or(SK::signal, "?"));
			}
			auto opts = seen | views::values | ranges::to<vector<ActorPtr>>();
			try{
				hw_capabilities::check_req_options(actors, opts);
				found = true;
				return true;
			} catch(const req_err &){}
		}
		return nullopt;
	};

	while(!found){
		for(const int ch_num: channels){
			if(found) break;
			log(LogLevel::INFO, "Scanning channel {} on {}", ch_num, iface);
			scanner->set_channel(Channel{ch_num, WifiBand::BAND_2_4, nullopt});
			this_thread::sleep_for(chrono::milliseconds(200));

			auto result = components::poll_sniffer<bool>(handle, chrono::milliseconds(20000), on_packet);
			if(holds_alternative<StopReason>(result) && get<StopReason>(result) == StopReason::Interrupted) break;
		}
	}
	return seen | views::values | ranges::to<vector<ActorPtr>>();
}

vector<ActorPtr> RunStatus::external_bb_options(const ActorCMap &actors){
	const vector<int> channels = get_external_BB_channels();
	if(channels.empty()) return {};
	const string iface = _config.at("scan_iface");
	const int timeout = get_global_config().at("timeout_external_bb_scan_sec").get<int>();

	if(_config.value("scan_until_success", false) && !actors.empty()) return scan_until_match(iface, channels, actors);

	return list_external_entities(iface, timeout, channels);
}
}