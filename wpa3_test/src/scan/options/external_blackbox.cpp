#include <pcap/pcap.h>
#include "attacks/components/sniffer_helper.h"
#include "config/global_config.h"
#include "config/RunStatus.h"
#include "config/Actor_Config/Actor_Config_external.h"
#include "config/Actor_Config/Actor_Config_internal.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"
#include "system/utils.h"

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
		actor->set(BK::AP, is_ap); //TODO different possibilities?
		actor->set(BK::STA, !is_ap);

		if(channel_freq > 0){
			if     (channel_freq >= 2412 && channel_freq <= 2484) actor[BK::GHz2_4] = true;
			else if(channel_freq >= 5170 && channel_freq <= 5885) actor[BK::GHz5]   = true;
			else if(channel_freq >= 5945 && channel_freq <= 7125) actor[BK::GHz6]   = true;
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
	} else if(const auto *data = pdu.find_pdu<Dot11Data>()){
		const bool to_ds   = data->to_ds();
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

vector<ActorPtr> RunStatus::list_external_entities(
	const string &iface, const size_t timeout_sec, const vector<int> &channels
){
	if(channels.empty()) throw setup_err("No channels specified for scanning");

	//setup scan iface
	const ActorPtr scanner(make_shared<Actor_Config_internal>());
	scanner->set(SK::iface, iface);
	scanner->set_monitor_mode();
	scanner->set_iface_up();

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_create(iface.c_str(), errbuf);
	if(!handle) throw setup_err("pcap_create failed: " + string(errbuf));

	pcap_set_snaplen(handle, 2000);
	pcap_set_promisc(handle, 1);
	pcap_set_rfmon(handle, 1);
	pcap_set_timeout(handle, 100);

	if(pcap_activate(handle) < 0){
		const string msg = pcap_geterr(handle);
		pcap_close(handle);
		throw setup_err("pcap_activate failed: " + msg);
	}
	struct PcapGuard{ pcap_t *h; ~PcapGuard(){ pcap_close(h); } } _guard{handle};

	ActorMACMap seen;
	constexpr size_t SEC_MINIMUM = 2;
	const size_t channel_sec = max<size_t>(SEC_MINIMUM, timeout_sec / channels.size());
	const auto total_end = chrono::steady_clock::now() + chrono::seconds(timeout_sec);

	for(const int channel: channels){
		if(chrono::steady_clock::now() >= total_end) break;
		log(LogLevel::INFO, "Scanning channel {} on {}", channel, iface);

		const Channel ch{channel, WifiBand::BAND_2_4, nullopt}; //FIXME only 2_4
		scanner->set_channel(ch);
		this_thread::sleep_for(chrono::milliseconds(200));

		components::poll_sniffer<monostate>(handle, chrono::milliseconds(channel_sec * 1000),
			[&](const uint8_t *pkt, const size_t len) -> optional<monostate>{
				try{ solve_new_pdu(vector(pkt, pkt + len), seen); } catch(...){}
				return nullopt;
			}
		);
	}
	return seen | views::values | ranges::to<vector<ActorPtr>>();
}

vector<int> RunStatus::get_external_BB_channels(){
	vector<int> all_channels;
	for(const auto &[actor_name, actor_config]: _config.at("actors").items()){
		if(actor_config.at("selection").contains("channel")){
			all_channels.push_back(actor_config.at("selection").at("channel").get<int>());
		} else{
			log(LogLevel::WARNING, "Actor {} missing channel configuration", actor_name);
		}
	}

	if(all_channels.empty()){
		log(LogLevel::WARNING, "No channels found in external actor configurations");
		return {};
	}

	ranges::sort(all_channels);
	all_channels.erase(ranges::unique(all_channels).begin(), all_channels.end());

	const auto s = all_channels | views::transform([](int c){ return to_string(c); })
	                            | views::join_with(string(", "))
	                            | ranges::to<string>();
	log(LogLevel::INFO, "Scanning channels: {}", s);
	return all_channels;
}

vector<ActorPtr> RunStatus::external_bb_options(){
	const vector<int> scan_channels = get_external_BB_channels();
	if(scan_channels.empty()) return {};
	const int timeout = get_global_config().at("timeout_external_bb_scan_sec").get<int>();
	return list_external_entities(_config.at("scan_iface"), timeout, scan_channels);
}

}