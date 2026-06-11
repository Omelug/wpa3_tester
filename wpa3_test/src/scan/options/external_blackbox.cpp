#include "attacks/scan/scan.h"
#include <fstream>
#include <sstream>
#include <tins/sniffer.h>
#include "config/global_config.h"
#include "config/RunStatus.h"
#include "config/Actor_Config/Actor_Config_external.h"
#include "config/Actor_Config/Actor_Config_internal.h"
#include "config/Actor_Config/Actor_Config_sim.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"
#include "system/hw_info.h"
#include "system/ip.h"
#include "system/utils.h"

namespace wpa3_tester{
using namespace std;
using nlohmann::json;
using namespace Tins;
using namespace filesystem;

// ------------- EXTERNAL
void RunStatus::solve_new_pdu(PDU &pdu, ActorMap &seen){
	int8_t signal = -1;
	int channel_freq = -1;

	if(const auto *radiotap = pdu.find_pdu<RadioTap>()){
		signal = radiotap->dbm_signal();
		channel_freq = radiotap->channel_freq();
	}

	const auto add_entity = [&](const string &mac, bool is_ap, const string &ssid = ""){
		ActorPtr actor;
		if(seen.contains(mac)){
			actor = seen.at(mac);
		} else{
			actor = ActorPtr(make_shared<Actor_Config_external>());
			seen.emplace(mac, actor);
		}
		actor->set(SK::mac, mac);
		actor->set(SK::ssid, ssid);
		actor->set(BK::AP, is_ap);

		if(channel_freq > 0){
			if(channel_freq >= 2412 && channel_freq <= 2484){
				actor[BK::GHz2_4] = true;
			} else if(channel_freq >= 5170 && channel_freq <= 5885){
				actor[BK::GHz5] = true;
			} else if(channel_freq >= 5945 && channel_freq <= 7125){
				actor[BK::GHz6] = true;
			}
			const int channel_num = hw_capabilities::freq_to_channel(channel_freq);
			actor->set(SK::channel, to_string(channel_num));
		}

		if(signal != -1){ actor->set(SK::signal, to_string(signal)); }
	};

	// AP: Beacon
	if(const auto *beacon = pdu.find_pdu<Dot11Beacon>()){
		const string mac = beacon->addr2().to_string();
		string ssid;
		try{ ssid = beacon->ssid(); } catch(...){}
		add_entity(mac, true, ssid);
	}
	// AP: Probe Response
	else if(const auto *probe_resp = pdu.find_pdu<Dot11ProbeResponse>()){
		const string mac = probe_resp->addr2().to_string();
		string ssid;
		try{ ssid = probe_resp->ssid(); } catch(...){}
		add_entity(mac, true, ssid);
	}
	// STA: Probe Request
	else if(const auto *probe_req = pdu.find_pdu<Dot11ProbeRequest>()){
		const string mac = probe_req->addr2().to_string();
		string ssid;
		try{ ssid = probe_req->ssid(); } catch(...){}
		add_entity(mac, false, ssid);
	}
	// Data frames
	else if(const auto *data = pdu.find_pdu<Dot11Data>()){
		const bool to_ds = data->to_ds();

		if(const bool from_ds = data->from_ds(); to_ds && !from_ds){
			// STA → AP
			add_entity(data->addr2().to_string(), false); // STA
			add_entity(data->addr1().to_string(), true);  // AP
		} else if(!to_ds && from_ds){
			// AP → STA
			add_entity(data->addr1().to_string(), false); // STA
			add_entity(data->addr2().to_string(), true);  // AP
		}
		// WDS/IBSS frames ignored
	}
}

vector<ActorPtr> RunStatus::list_external_entities(const string &iface, const size_t timeout_sec,
													const vector<int> &channels
){
	ActorMap seen;
	if(channels.empty()) throw setup_err("No channels specified for scanning");

	SnifferConfiguration config;
	config.set_promisc_mode(true);
	config.set_rfmon(true);
	config.set_timeout(10);

	const auto total_end_time = chrono::steady_clock::now() + chrono::seconds(timeout_sec);
	// one channel time
	constexpr size_t SEC_MINIMUM = 2;
	const size_t channel_sec = max<size_t>(SEC_MINIMUM, timeout_sec / channels.size());

	for(const int channel: channels){
		if(chrono::steady_clock::now() >= total_end_time) break;
		log(LogLevel::INFO, "Scanning channel {} on {}", channel, iface);

		string set_channel_cmd = "iw dev " + iface + " set channel " + to_string(channel);
		if(system(set_channel_cmd.c_str()) != 0){
			log(LogLevel::ERROR, "Failed to set channel {}", channel);
		}
		this_thread::sleep_for(chrono::milliseconds(200));

		Sniffer sniffer(iface, config);
		auto channel_end_time = chrono::steady_clock::now() + chrono::seconds(channel_sec);

		while(true){
			auto now = chrono::steady_clock::now();
			if(now >= channel_end_time || now >= total_end_time) break;

			sniffer.sniff_loop([&](PDU &pdu){
				try{
					solve_new_pdu(pdu, seen);
				} catch(...){}
				return chrono::steady_clock::now() < channel_end_time;
			}, 1); // solve only one packet
		}
	}
	return seen | views::values | ranges::to<vector<ActorPtr>>();
}

vector<int> RunStatus::get_external_BB_channels(){
	//get channels from external actors
	vector<int> all_channels;
	for(const auto &[actor_name, actor_config]: _config.at("actors").items()){
		if(actor_config.at("selection").contains("channel")){
			int channel = actor_config.at("selection").at("channel");
			all_channels.push_back(channel);
		} else{
			log(LogLevel::WARNING, "Actor {} missing channel configuration", actor_name);
		}
	}

	if(all_channels.empty()){
		log(LogLevel::WARNING, "No channels found in external actor configurations");
		return {};
	}

	// Remove duplicates and sort
	ranges::sort(all_channels);
	all_channels.erase(ranges::unique(all_channels).begin(), all_channels.end());

	{
		string channels_str;
		for(size_t i = 0; i < all_channels.size(); ++i){
			channels_str += to_string(all_channels[i]);
			if(i < all_channels.size() - 1) channels_str += ", ";
		}
		log(LogLevel::INFO, "Scanning channels: {}", channels_str);
	}

	return all_channels;
}

vector<ActorPtr> RunStatus::external_bb_options(){
	const vector<int> all_channels = get_external_BB_channels();
	if(all_channels.empty()){ return {}; }
	const int timeout_external_bb_scan = get_global_config().at("timeout_external_bb_scan").get<int>();
	return list_external_entities(_config.at("scan_iface"), timeout_external_bb_scan, all_channels);
}

}
